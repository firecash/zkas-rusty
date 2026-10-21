//! Compatibility adapters for dependencies that still use `rand_core` 0.6.

use rand::Rng;

/// The infallible OS RNG interface that `rand_core` 0.6 exposed as `OsRng`.
#[cfg(test)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OsRng;

#[cfg(test)]
impl rand::TryRng for OsRng {
    type Error = rand::rand_core::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rand::rand_core::UnwrapErr(rand::rngs::SysRng).try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rand::rand_core::UnwrapErr(rand::rngs::SysRng).try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        rand::rand_core::UnwrapErr(rand::rngs::SysRng).try_fill_bytes(dest)
    }
}

#[cfg(test)]
impl rand::TryCryptoRng for OsRng {}

pub(crate) struct RngCore06<'a, R: ?Sized>(&'a mut R);

impl<'a, R: Rng + ?Sized> RngCore06<'a, R> {
    pub(crate) fn new(rng: &'a mut R) -> Self {
        Self(rng)
    }
}

impl<R: Rng + ?Sized> rand_core_06::RngCore for RngCore06<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
