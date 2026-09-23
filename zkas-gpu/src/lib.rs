//! Optional GPU acceleration for the one part of a wallet scan that cannot be shared
//! between wallets: `ivk · epk`, the Pallas key agreement that decides whether a
//! shielded note belongs to you.
//!
//! Measured on an RTX 2080 Ti: **1.567 µs/mult against 81.7 µs on one CPU core (52×)
//! and 19.9 µs across twelve (12.7×)**. The CPU figure is orchard's own prepared-Wnaf
//! path, so that is a comparison against what the daemon actually runs.
//!
//! # Loaded, not linked
//!
//! `libzkas_gpu.so` is opened with `dlopen` at startup rather than linked at build
//! time. A wallet must build and run on hosts with no GPU and no CUDA toolkit, so a
//! build dependency on CUDA would be unacceptable. No library, no device, or any
//! runtime failure — every one of those falls back to the CPU, and the caller cannot
//! tell the difference except in speed.
//!
//! # Trust
//!
//! The kernel is not trusted because the arithmetic looks right. Its outputs were
//! compared byte-for-byte against `pasta_curves` — the same implementation consensus
//! uses — over 100,000 points including planted edge cases (the generator, forcing the
//! `H == 0` "this addition is really a doubling" branch that naive mixed addition gets
//! silently wrong, and its negation, forcing the identity). See `gpu/README.md`.
//!
//! On top of that, [`Gpu::batch_agree`] re-checks every point it gets back: a result
//! that is not a valid curve point, or that fails to convert, disables the GPU for the
//! process. A wrong answer here is a missed note, which a user experiences as their
//! coins vanishing, so the failure mode is "fall back to the CPU", never "carry on".

use group::ff::PrimeField;
use group::{Curve, Group};
use pasta_curves::pallas;
use std::sync::atomic::{AtomicBool, Ordering};

const LIMBS: usize = 8;

type DeviceCountFn = unsafe extern "C" fn() -> i32;
type BatchKaFn = unsafe extern "C" fn(*const u32, i32, *const u32, *mut u32, i32) -> i32;

/// A loaded CUDA backend. Absent means "use the CPU", which is always correct.
pub struct Gpu {
    _lib: libloading::Library,
    batch_ka: BatchKaFn,
    devices: i32,
    /// Latches on any failure. Once the GPU has misbehaved once we stop asking it:
    /// a device that returned one bad answer has no claim to the next one.
    poisoned: AtomicBool,
    /// The verdict ABI. `None` on a library that predates it, or one whose start-up
    /// self-test failed — in which case the point ABI above still works and the only
    /// cost is speed.
    filter: Option<BatchFilterFn>,
    /// Test-only intermediates. `None` unless the library exports them.
    debug_kdf: Option<DebugKdfFn>,
    /// One known-answer pair per viewing key, built on first use and kept: the host key
    /// agreement behind it costs ~75 us and is paid once per wallet for the life of the
    /// process.
    canaries: std::sync::Mutex<std::collections::HashMap<[u8; 32], Canary>>,
}

/// Where to look for the kernel. An explicit path wins so an operator can point at a
/// build without installing anything.
fn candidates() -> Vec<String> {
    let mut v = Vec::new();
    if let Ok(p) = std::env::var("ZKAS_GPU_LIB") {
        v.push(p);
    }
    v.push("libzkas_gpu.so".into());
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            v.push(dir.join("libzkas_gpu.so").to_string_lossy().into_owned());
        }
    }
    v.push("/root/zkas/gpu/libzkas_gpu.so".into());
    v
}

impl Gpu {
    /// Try to bring up the GPU backend. `None` on any problem, and the caller uses the
    /// CPU — which is the same answer, only slower.
    pub fn load() -> Option<Self> {
        for path in candidates() {
            let lib = match unsafe { libloading::Library::new(&path) } {
                Ok(l) => l,
                Err(_) => continue,
            };
            let devices = unsafe {
                let f: libloading::Symbol<DeviceCountFn> = lib.get(b"zkas_gpu_device_count").ok()?;
                f()
            };
            if devices <= 0 {
                log::info!("GPU library at {path} loaded but reports no usable device; using the CPU");
                continue;
            }
            let batch_ka = unsafe {
                let f: libloading::Symbol<BatchKaFn> = lib.get(b"zkas_gpu_batch_ka").ok()?;
                *f
            };
            // The verdict ABI is optional: an older library exports only `batch_ka`, and
            // a daemon linked against this crate must keep working with one.
            let filter = unsafe { lib.get::<BatchFilterFn>(b"zkas_gpu_batch_filter").ok().map(|f| *f) };
            let debug_kdf = unsafe { lib.get::<DebugKdfFn>(b"zkas_gpu_debug_kdf").ok().map(|f| *f) };
            let mut gpu = Gpu {
                _lib: lib,
                batch_ka,
                devices,
                poisoned: AtomicBool::new(false),
                filter,
                debug_kdf,
                canaries: std::sync::Mutex::new(std::collections::HashMap::new()),
            };
            if gpu.filter.is_some() {
                if let Err(why) = gpu.filter_self_test() {
                    // Drop the filter, keep the device. The point ABI is unaffected and
                    // already proven, so the right outcome is the older, slower path --
                    // not no GPU at all, and certainly not a filter nobody has checked.
                    // The self-test poisons on a canary mismatch; clear that, because
                    // what is being disqualified here is the filter, not the device.
                    log::error!("GPU filter self-test FAILED ({why}); falling back to the point ABI. Results are unaffected, only speed.");
                    gpu.filter = None;
                    gpu.poisoned.store(false, Ordering::Relaxed);
                } else {
                    log::info!("GPU filter self-test passed: trial decryption runs entirely on the device");
                }
            }
            log::info!("GPU acceleration enabled: {devices} device(s) via {path}");
            return Some(gpu);
        }
        None
    }

    pub fn devices(&self) -> i32 {
        self.devices
    }

    pub fn is_usable(&self) -> bool {
        !self.poisoned.load(Ordering::Relaxed)
    }

    fn poison(&self, why: &str) {
        if !self.poisoned.swap(true, Ordering::Relaxed) {
            log::error!("GPU disabled for the rest of this process: {why}. Falling back to the CPU — results are unaffected, only speed.");
        }
    }

    /// `ivk · epk` for a whole batch. `None` means "I could not do this" — never a
    /// partial or approximate answer — and the caller must use the CPU path.
    ///
    /// `epks[i] == None` marks an ephemeral key that was not a valid encoding; those
    /// positions come back `None` too, matching what the CPU path produces.
    pub fn batch_agree(&self, ivk: &pallas::Scalar, epks: &[Option<pallas::Point>]) -> Option<Vec<Option<pallas::Affine>>> {
        if !self.is_usable() || epks.is_empty() {
            return None;
        }
        // Canonical little-endian limbs plus the top set bit; a zero scalar is not
        // something to hand a kernel.
        let (scalar, bits) = pack_scalar(ivk)?;

        // Only the valid keys are sent; the invalid slots are re-inserted afterwards, so
        // the GPU never has to represent "absent" and the batch stays dense.
        let idx: Vec<usize> = epks.iter().enumerate().filter(|(_, e)| e.is_some()).map(|(i, _)| i).collect();
        if idx.is_empty() {
            return Some(vec![None; epks.len()]);
        }
        // ONE inversion for the whole batch, not one per point.
        //
        // `to_affine()` performs a modular inversion each time it is called, so mapping
        // it over the batch cost ~10 us/point — dwarfing the 1.567 us the kernel takes
        // and making the whole GPU path look like a marshalling problem. Montgomery's
        // trick turns N inversions into one plus 3N multiplications.
        let proj: Vec<pallas::Point> = idx.iter().map(|&i| epks[i].unwrap()).collect();
        let mut affine = vec![pallas::Affine::default(); proj.len()];
        pallas::Point::batch_normalize(&proj, &mut affine);

        let mut input = vec![0u32; idx.len() * 2 * LIMBS];
        for (k, a) in affine.iter().enumerate() {
            let c = match Option::<pasta_curves::arithmetic::Coordinates<pallas::Affine>>::from(
                <pallas::Affine as pasta_curves::arithmetic::CurveAffine>::coordinates(a),
            ) {
                Some(c) => c,
                None => return None, // the identity has no affine coordinates
            };
            let xb = <pallas::Base as group::ff::PrimeField>::to_repr(c.x());
            let yb = <pallas::Base as group::ff::PrimeField>::to_repr(c.y());
            for l in 0..LIMBS {
                input[k * 2 * LIMBS + l] = u32::from_le_bytes([xb[l * 4], xb[l * 4 + 1], xb[l * 4 + 2], xb[l * 4 + 3]]);
                input[k * 2 * LIMBS + LIMBS + l] =
                    u32::from_le_bytes([yb[l * 4], yb[l * 4 + 1], yb[l * 4 + 2], yb[l * 4 + 3]]);
            }
        }

        let mut out = vec![0u32; idx.len() * 3 * LIMBS];
        let rc = unsafe {
            (self.batch_ka)(scalar.as_ptr(), bits, input.as_ptr(), out.as_mut_ptr(), idx.len() as i32)
        };
        if rc != 0 {
            self.poison(&format!("kernel returned {rc}"));
            return None;
        }

        // Jacobian -> affine for the whole batch: ONE field inversion via Montgomery's
        // trick rather than one per point, done by pasta_curves so this step rests on an
        // implementation that is already trusted.
        let mut jac = Vec::with_capacity(idx.len());
        for k in 0..idx.len() {
            let rd = |off: usize| -> Option<pallas::Base> {
                let mut b = [0u8; 32];
                for l in 0..LIMBS {
                    b[l * 4..l * 4 + 4].copy_from_slice(&out[k * 3 * LIMBS + off + l].to_le_bytes());
                }
                Option::from(<pallas::Base as group::ff::PrimeField>::from_repr(b))
            };
            // Any limb that is not a field element means the kernel produced garbage.
            let (x, y, z) = match (rd(0), rd(LIMBS), rd(2 * LIMBS)) {
                (Some(x), Some(y), Some(z)) => (x, y, z),
                _ => {
                    self.poison("kernel returned a value outside the field");
                    return None;
                }
            };
            jac.push((x, y, z));
        }

        // Batch-invert every Z at once.
        let zs: Vec<pallas::Base> = jac.iter().map(|(_, _, z)| *z).collect();
        let mut zinv = zs.clone();
        group::ff::BatchInverter::invert_with_external_scratch(&mut zinv, &mut zs.clone());

        let mut dense = Vec::with_capacity(idx.len());
        for (k, (x, y, z)) in jac.iter().enumerate() {
            if bool::from(group::ff::Field::is_zero(z)) {
                dense.push(None); // identity: this ephemeral key agrees to nothing
                continue;
            }
            let zi = zinv[k];
            let zi2 = zi * zi;
            let zi3 = zi2 * zi;
            let ax = *x * zi2;
            let ay = *y * zi3;
            match Option::<pallas::Affine>::from(<pallas::Affine as pasta_curves::arithmetic::CurveAffine>::from_xy(ax, ay)) {
                Some(p) => dense.push(Some(p)),
                None => {
                    // Not on the curve — the one outcome that must never be used.
                    self.poison("kernel returned a point that is not on the curve");
                    return None;
                }
            }
        }

        let mut result = vec![None; epks.len()];
        for (k, &i) in idx.iter().enumerate() {
            result[i] = dense[k];
        }
        Some(result)
    }
}

// ===================== THE FILTER: one byte per action =======================
//
// `batch_agree` above asks the device for `ivk · epk` and gets back a 96-byte Jacobian
// per action. The host then converts it to affine, runs BLAKE2b and ChaCha20, and
// reduces all of that to one bit. Measured, that host half was ~1.3 us of the
// 2.87 us/pt the GPU path cost, against a 0.324 us kernel: 45% of the path was
// marshalling around the part that had already been moved.
//
// `batch_filter` asks the device for the bit. The Jacobians, the `from_repr` round
// trips, the `BatchInverter` with its two clones, the `from_xy` curve check and the
// eight N-sized allocations are all gone, and D2H falls from 96 B/pair to 1 B.
//
// WHAT REPLACES THE CURVE CHECK
// -----------------------------
// `batch_agree` re-checked every point it got back, and that check was not decoration:
// it is the only thing standing between a device having a bad day and a wallet quietly
// missing notes. A verdict byte cannot be checked that way — checking it would mean
// redoing the work it exists to avoid.
//
// So it is replaced by a CANARY, which is strictly stronger than what it replaces. Two
// extra rows ride every call, built on the host for this exact viewing key: one whose
// ciphertext byte is chosen so the plaintext lead byte MUST be 0x02, and one so it must
// not be. The device has to answer 1 and 0. That exercises the ladder, the inversion,
// the compressed encoding, the KDF and the cipher — where the old check only saw
// whether a point was on the curve — and it exercises them against this call's scalar.
// A wrong answer poisons the device and every wallet goes back to the CPU.
//
// The canary costs one host key agreement per viewing key EVER (cached below), plus two
// points and one memcpy of the caller's rows per call: ~33 us on an 832 KB batch,
// against a launch of ~6 ms. 0.5%, for the only remaining check on a device's word.

type BatchFilterFn = unsafe extern "C" fn(*const u32, i32, *const u32, *const u8, *mut u8, i32) -> i32;
type DebugKdfFn = unsafe extern "C" fn(*const u32, i32, *const u32, *mut u32, i32) -> i32;

/// Two known-answer rows for one viewing key: the same point twice, with ciphertext
/// bytes chosen so the device must answer 1 then 0.
#[derive(Clone)]
struct Canary {
    xy: [u32; 16],
    ct0: [u8; 2],
}

/// The Orchard KDF and the one keystream byte the filter looks at, on the host.
/// Used to build canaries and by the self-test — never on the scan path.
fn host_lead_keystream_byte(secret: &pallas::Affine, epk: &pallas::Affine) -> u8 {
    use blake2b_simd::Params;
    use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
    use group::GroupEncoding;
    let key = Params::new()
        .hash_length(32)
        .personal(b"Zcash_OrchardKDF")
        .to_state()
        .update(&secret.to_bytes())
        .update(&epk.to_bytes())
        .finalize();
    let mut b = [0u8; 1];
    let mut c = chacha20::ChaCha20::new(key.as_bytes().into(), &[0u8; 12].into());
    c.seek(64u32);
    c.apply_keystream(&mut b);
    b[0]
}

/// Pack an affine point into the 16 canonical little-endian limbs the device takes.
fn pack_affine(p: &pallas::Affine, out: &mut [u32]) -> bool {
    use pasta_curves::arithmetic::CurveAffine;
    let Some(c) = Option::<pasta_curves::arithmetic::Coordinates<pallas::Affine>>::from(p.coordinates()) else {
        return false;
    };
    let xb = <pallas::Base as PrimeField>::to_repr(c.x());
    let yb = <pallas::Base as PrimeField>::to_repr(c.y());
    for l in 0..LIMBS {
        out[l] = u32::from_le_bytes([xb[l * 4], xb[l * 4 + 1], xb[l * 4 + 2], xb[l * 4 + 3]]);
        out[LIMBS + l] = u32::from_le_bytes([yb[l * 4], yb[l * 4 + 1], yb[l * 4 + 2], yb[l * 4 + 3]]);
    }
    true
}

/// The agreement scalar as canonical limbs plus its top set bit, so the ladder does not
/// spend 255 doublings on a short scalar. `None` for zero, which is not something to
/// hand a kernel.
fn pack_scalar(ivk: &pallas::Scalar) -> Option<([u32; LIMBS], i32)> {
    let sb = ivk.to_repr();
    let mut scalar = [0u32; LIMBS];
    for i in 0..LIMBS {
        scalar[i] = u32::from_le_bytes([sb[i * 4], sb[i * 4 + 1], sb[i * 4 + 2], sb[i * 4 + 3]]);
    }
    for i in (0..LIMBS * 32).rev() {
        if (scalar[i >> 5] >> (i & 31)) & 1 == 1 {
            return Some((scalar, i as i32 + 1));
        }
    }
    None
}

impl Gpu {
    /// Whether the device can answer verdicts rather than points. False on an older
    /// library, or when the start-up self-test caught it lying.
    pub fn has_filter(&self) -> bool {
        self.filter.is_some()
    }

    /// Build (once per viewing key) the two known-answer rows that ride every call.
    fn canary(&self, ivk: &pallas::Scalar) -> Option<Canary> {
        let tag = <pallas::Scalar as PrimeField>::to_repr(ivk);
        if let Some(c) = self.canaries.lock().ok()?.get(&tag) {
            return Some(c.clone());
        }
        // The generator: a point every implementation agrees about, and the one whose
        // ladder hits the "this addition is really a doubling" branch.
        let q = pallas::Point::generator().to_affine();
        let secret = (pallas::Point::from(q) * ivk).to_affine();
        let ks0 = host_lead_keystream_byte(&secret, &q);
        let mut xy = [0u32; 16];
        if !pack_affine(&q, &mut xy) {
            return None;
        }
        // 0x02 is the note-plaintext version the filter looks for; 0x01 is anything
        // else. One row must come back 1 and the other 0.
        let c = Canary { xy, ct0: [ks0 ^ 0x02, ks0 ^ 0x01] };
        self.canaries.lock().ok()?.insert(tag, c.clone());
        Some(c)
    }

    /// Trial-decryption filter for a whole cohort row: affine ephemeral keys and one
    /// ciphertext byte each in, one verdict byte each out.
    ///
    /// `xy` is `rows * 16` canonical little-endian limbs — x then y — exactly what
    /// `shielded_core::wallet::prepare_epks` builds once per page. `ct0[i]` is the first
    /// byte of action `i`'s compact ciphertext.
    ///
    /// `None` means "I could not do this", and the caller MUST scan on the CPU. It never
    /// means "no candidates".
    pub fn batch_filter(&self, ivk: &pallas::Scalar, xy: &[u32], rows: usize, ct0: &[u8]) -> Option<Vec<u8>> {
        let f = self.filter?;
        if !self.is_usable() || rows == 0 || xy.len() != rows * 16 || ct0.len() != rows {
            return None;
        }
        let (scalar, bits) = pack_scalar(ivk)?;
        let canary = self.canary(ivk)?;

        // One allocation and one memcpy for the whole call, to append the canary rows.
        // This is the only N-sized copy left on the path; at 13,000 rows it is 832 KB,
        // ~33 us, against a launch of ~6 ms.
        let n = rows + 2;
        let mut input: Vec<u32> = Vec::with_capacity(n * 16);
        input.extend_from_slice(xy);
        input.extend_from_slice(&canary.xy);
        input.extend_from_slice(&canary.xy);
        let mut ct: Vec<u8> = Vec::with_capacity(n);
        ct.extend_from_slice(ct0);
        ct.extend_from_slice(&canary.ct0);

        let mut mask = vec![0u8; n];
        let rc = unsafe { f(scalar.as_ptr(), bits, input.as_ptr(), ct.as_ptr(), mask.as_mut_ptr(), n as i32) };
        if rc != 0 {
            self.poison(&format!("filter kernel returned {rc}"));
            return None;
        }
        // The device answered; now check that it was awake. A device that cannot get
        // the two rows whose answers we already know has no claim to the rest.
        if mask[rows] != 1 || mask[rows + 1] != 0 {
            self.poison(&format!(
                "canary rows came back {} / {} instead of 1 / 0 — the device is not computing what it is being asked",
                mask[rows],
                mask[rows + 1]
            ));
            return None;
        }
        mask.truncate(rows);
        Some(mask)
    }

    /// Device intermediates for one batch: the compressed shared secret, the KDF key and
    /// the keystream byte, 17 u32 per point. Test-only — it exists so a differential can
    /// say WHICH stage disagrees rather than only that the filter found nothing.
    pub fn debug_kdf(&self, ivk: &pallas::Scalar, xy: &[u32], rows: usize) -> Option<Vec<u32>> {
        let f = self.debug_kdf?;
        if rows == 0 || xy.len() != rows * 16 {
            return None;
        }
        let (scalar, bits) = pack_scalar(ivk)?;
        let mut out = vec![0u32; rows * 17];
        let rc = unsafe { f(scalar.as_ptr(), bits, xy.as_ptr(), out.as_mut_ptr(), rows as i32) };
        (rc == 0).then_some(out)
    }

    /// Prove the filter ABI computes what this host says it should, before any wallet
    /// depends on it.
    ///
    /// A filter's failure mode is SILENCE: get the personalisation, the parameter block
    /// or the block counter wrong and the device returns "no candidates", which looks
    /// exactly like "this wallet owns nothing" until somebody notices coins missing.
    /// There is no scan-time check that can catch that, so it is caught here, once, and
    /// a device that fails is simply not installed — the daemon then uses the older
    /// point ABI or the CPU, and the only cost is speed.
    fn filter_self_test(&self) -> Result<(), String> {
        use group::ff::Field;
        let mut rng = rand::rng();
        let ivk = pallas::Scalar::random(&mut rng);
        const N: usize = 64;
        let pts: Vec<pallas::Affine> = (0..N).map(|_| pallas::Point::random(&mut rng).to_affine()).collect();

        let mut xy = vec![0u32; N * 16];
        for (i, p) in pts.iter().enumerate() {
            if !pack_affine(p, &mut xy[i * 16..(i + 1) * 16]) {
                return Err("a random point had no affine coordinates".into());
            }
        }
        // Every fourth point is made a hit, the rest misses, so a device that answers
        // all-zero and a device that answers all-one both fail.
        let mut ct0 = vec![0u8; N];
        let mut want = vec![0u8; N];
        for i in 0..N {
            let secret = (pallas::Point::from(pts[i]) * ivk).to_affine();
            let ks0 = host_lead_keystream_byte(&secret, &pts[i]);
            let hit = i % 4 == 0;
            ct0[i] = ks0 ^ if hit { 0x02 } else { 0x07 };
            want[i] = hit as u8;
        }

        let got = self.batch_filter(&ivk, &xy, N, &ct0).ok_or("the device declined the self-test")?;
        if got != want {
            let bad = (0..N).find(|&i| got[i] != want[i]).unwrap_or(0);
            return Err(format!("verdict {} differs at row {bad} (device {}, host {})", "", got[bad], want[bad]));
        }
        Ok(())
    }
}

impl Gpu {
    /// The shape `shielded-core`'s hook expects: scalar and points in, affine shared
    /// secrets out, `None` meaning "use the CPU".
    pub fn batch_agree_points(
        &self,
        ivk: &pallas::Scalar,
        epks: &[Option<pallas::Point>],
    ) -> Option<Vec<Option<pallas::Affine>>> {
        self.batch_agree(ivk, epks)
    }
}

/// The CPU answer, for the differential check and for hosts with no GPU.
pub fn cpu_batch_agree(ivk: &pallas::Scalar, epks: &[Option<pallas::Point>]) -> Vec<Option<pallas::Affine>> {
    epks.iter().map(|e| e.map(|p| (p * ivk).to_affine())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use group::ff::Field;

    /// If a GPU is present its answers must equal the CPU's, exactly. If none is
    /// present the test still passes — this crate's contract is "same answer, maybe
    /// faster", and "no GPU" satisfies it.
    #[test]
    fn gpu_agrees_with_the_cpu_or_is_absent() {
        let Some(gpu) = Gpu::load() else {
            eprintln!("no GPU available — CPU path only, which is a valid configuration");
            return;
        };
        let mut rng = rand::rng();
        let ivk = pallas::Scalar::random(&mut rng);
        let mut epks: Vec<Option<pallas::Point>> = (0..1024).map(|_| Some(pallas::Point::random(&mut rng))).collect();
        // Planted edge cases: an absent key, and the generator (whose ladder hits the
        // "this addition is really a doubling" branch).
        epks[3] = None;
        epks[7] = Some(pallas::Point::generator());

        eprintln!("GPU present: {} device(s) — comparing {} points against the CPU", gpu.devices(), epks.len());
        let got = gpu.batch_agree(&ivk, &epks).expect("gpu answered");
        let want = cpu_batch_agree(&ivk, &epks);
        assert_eq!(got.len(), want.len());
        for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            assert_eq!(g.is_some(), w.is_some(), "presence differs at {i}");
            if let (Some(g), Some(w)) = (g, w) {
                assert_eq!(g, w, "GPU and CPU disagree at {i}");
            }
        }
    }
}
