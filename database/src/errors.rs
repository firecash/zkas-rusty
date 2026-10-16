use crate::prelude::DbKey;
use kaspa_hashes::Hash;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("key {0} not found in store")]
    KeyNotFound(DbKey),

    #[error("key {0} already exists in store")]
    KeyAlreadyExists(String),

    /// Specialization of key already exists for the common `Hash` case.
    /// Added for avoiding the `String` allocation
    #[error("hash {0} already exists in store")]
    HashAlreadyExists(Hash),

    #[error("data inconsistency: {0}")]
    DataInconsistency(String),

    #[error("rocksdb error {0}")]
    DbError(#[from] rocksdb::Error),

    #[error("bincode error {0}")]
    DeserializationError(#[from] Box<bincode::ErrorKind>),
}

pub type StoreResult<T> = std::result::Result<T, StoreError>;

/// Predicates that classify store errors into common semantic buckets.
///
/// This is used by result extension methods (e.g. `optional`, `idempotent`)
/// to treat certain expected error conditions as benign outcomes.
pub trait StoreErrorPredicates {
    /// Returns `true` if this error represents a missing entry (e.g. key not found).
    fn is_key_not_found(&self) -> bool;

    /// Returns `true` if this error represents a duplicate write (e.g. key/hash already exists).
    fn is_already_exists(&self) -> bool;
}

impl StoreErrorPredicates for StoreError {
    fn is_key_not_found(&self) -> bool {
        matches!(self, StoreError::KeyNotFound(_))
    }

    fn is_already_exists(&self) -> bool {
        matches!(self, StoreError::KeyAlreadyExists(_) | StoreError::HashAlreadyExists(_))
    }
}

/// Extension methods for store results.
pub trait StoreResultExt<T, E: StoreErrorPredicates> {
    /// Converts a "key not found" error into absence.
    ///
    /// Mapping:
    /// - `Ok(v)` -> `Ok(Some(v))`
    /// - `Err(e)` where `e.is_key_not_found()` -> `Ok(None)`
    /// - any other `Err(e)` -> `Err(e)`
    ///
    /// This method does **not** panic.
    fn optional(self) -> Result<Option<T>, E>;
}

impl<T, E: StoreErrorPredicates> StoreResultExt<T, E> for Result<T, E> {
    fn optional(self) -> Result<Option<T>, E> {
        match self {
            Ok(value) => Ok(Some(value)),
            Err(err) if err.is_key_not_found() => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// Extension methods for unit (`()`) store results, typically produced by write operations.
pub trait StoreResultUnitExt<E: StoreErrorPredicates> {
    /// Treats a duplicate-write error as success, making the operation idempotent.
    ///
    /// Mapping:
    /// - `Ok(())` -> `Ok(())`
    /// - `Err(e)` where `e.is_already_exists()` -> `Ok(())`
    /// - any other `Err(e)` -> `Err(e)`
    ///
    /// This method does **not** panic.
    fn idempotent(self) -> Result<(), E>;
}

impl<E: StoreErrorPredicates> StoreResultUnitExt<E> for Result<(), E> {
    fn idempotent(self) -> Result<(), E> {
        match self {
            Ok(()) => Ok(()),
            Err(err) if err.is_already_exists() => Ok(()),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_found() -> StoreError {
        StoreError::KeyNotFound(DbKey::prefix_only(b"missing"))
    }

    /// Every error that is NOT a missing key. Each one is a store that could not answer, and
    /// none of them may come out of `optional()` as "absent".
    fn unreadable() -> Vec<StoreError> {
        vec![
            StoreError::DataInconsistency("corrupt row".to_owned()),
            StoreError::DeserializationError(Box::new(bincode::ErrorKind::Custom("truncated value".to_owned()))),
            StoreError::KeyAlreadyExists("dup".to_owned()),
            StoreError::HashAlreadyExists(Hash::from_bytes([7; 32])),
        ]
    }

    #[test]
    fn optional_maps_only_key_not_found_to_absent() {
        assert!(matches!(StoreResult::Ok(5u64).optional(), Ok(Some(5))));
        assert!(matches!(StoreResult::<u64>::Err(not_found()).optional(), Ok(None)));
        for err in unreadable() {
            let shown = format!("{err:?}");
            match StoreResult::<u64>::Err(err).optional() {
                Err(e) => assert_eq!(format!("{e:?}"), shown, "the error must come back unchanged"),
                Ok(v) => panic!("{shown} was folded into {v:?}; an unreadable store is not an absent key"),
            }
        }
    }

    #[test]
    fn optional_then_default_keeps_errors_out_of_the_default() {
        // The shape every verdict-path caller uses: absence picks the default, an IO fault
        // propagates. `unwrap_or(default)` on the raw result would have picked the default for both.
        let read = |r: StoreResult<u64>| r.optional().map(|v| v.unwrap_or(0));
        assert_eq!(read(Ok(9)).unwrap(), 9);
        assert_eq!(read(Err(not_found())).unwrap(), 0);
        for err in unreadable() {
            assert!(read(Err(err)).is_err());
        }
    }

    #[test]
    fn predicates_partition_the_error_kinds() {
        assert!(not_found().is_key_not_found());
        assert!(!not_found().is_already_exists());
        for err in unreadable() {
            assert!(!err.is_key_not_found(), "{err:?} is not a missing key");
        }
        assert!(StoreError::KeyAlreadyExists("k".to_owned()).is_already_exists());
        assert!(StoreError::HashAlreadyExists(Hash::from_bytes([1; 32])).is_already_exists());
        assert!(!StoreError::DataInconsistency("x".to_owned()).is_already_exists());
    }

    #[test]
    fn idempotent_absorbs_only_duplicate_writes() {
        assert!(Ok::<(), StoreError>(()).idempotent().is_ok());
        assert!(Err::<(), StoreError>(StoreError::KeyAlreadyExists("k".to_owned())).idempotent().is_ok());
        assert!(Err::<(), StoreError>(StoreError::HashAlreadyExists(Hash::from_bytes([2; 32]))).idempotent().is_ok());
        assert!(Err::<(), StoreError>(not_found()).idempotent().is_err());
        assert!(Err::<(), StoreError>(StoreError::DataInconsistency("x".to_owned())).idempotent().is_err());
    }
}
