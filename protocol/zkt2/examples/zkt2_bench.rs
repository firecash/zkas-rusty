//! M1 (spec 06 §11): ZKT2 handshake CPU and packet-layer throughput on this machine.
//!
//! `cargo run --release -p kaspa-zkt2 --example zkt2_bench [handshakes] [megabytes]`
//!
//! Runs on a current-thread runtime over in-memory pipes, so wall time is CPU time of one core
//! for both ends together (no network).

use kaspa_zkt2::cipher::{PacketDecryptor, PacketEncryptor, zkas_salt};
use kaspa_zkt2::stream::{HandshakeConfig, SNIFF_LEN, Zkt2Stream};
use secp256k1::SecretKey;
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let handshakes: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let megabytes: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(512);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();

    // 1. ElligatorSwift key creation + BIP 324 x-only ECDH, one side.
    let n = 5000;
    let sk2 = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let theirs = ElligatorSwift::from_seckey(&**secp256k1::SECP256K1, sk2, None);
    let t = Instant::now();
    for i in 0..n {
        let mut b = [1u8; 32];
        b[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        let sk = SecretKey::from_slice(&b).unwrap();
        let ours = ElligatorSwift::from_seckey(&**secp256k1::SECP256K1, sk, Some([3u8; 32]));
        let s = ElligatorSwift::shared_secret(ours, theirs, sk, ElligatorSwiftParty::A, None);
        std::hint::black_box(s);
    }
    let ecdh_us = t.elapsed().as_secs_f64() * 1e6 / n as f64;
    println!("ellswift keygen + xonly ECDH, one side: {ecdh_us:.1} us");

    // 2. Full handshakes (both sides, in-memory), with BIP 324's uniform 0..4095 B garbage.
    let cfg = HandshakeConfig::new(zkas_salt("zkas-mainnet"));
    let t = Instant::now();
    rt.block_on(async {
        for _ in 0..handshakes {
            let (a, mut b) = duplex(1 << 16);
            let c2 = cfg.clone();
            let resp = tokio::spawn(async move {
                let mut prefix = [0u8; SNIFF_LEN];
                b.read_exact(&mut prefix).await.unwrap();
                Zkt2Stream::respond(b, &prefix, &c2).await.unwrap()
            });
            let i = Zkt2Stream::initiate(a, &cfg).await.unwrap();
            let r = resp.await.unwrap();
            assert_eq!(i.session_id(), r.session_id());
        }
    });
    let hs_us = t.elapsed().as_secs_f64() * 1e6 / handshakes as f64;
    println!("full ZKT2 handshake, both sides: {hs_us:.1} us ({handshakes} runs)");

    // 3. Raw packet layer: encrypt + decrypt 16 KiB packets.
    let pkt = 16 * 1024;
    let total = megabytes * 1024 * 1024;
    let mut enc = PacketEncryptor::new([1u8; 32], [2u8; 32]);
    let mut dec = PacketDecryptor::new([1u8; 32], [2u8; 32]);
    let data = vec![0x5au8; pkt];
    let mut out = Vec::with_capacity(pkt + 32);
    let t = Instant::now();
    let mut done = 0;
    while done < total {
        out.clear();
        enc.encrypt_packet(&data, &[], false, &mut out);
        let len = dec.decrypt_length([out[0], out[1], out[2]]);
        assert_eq!(len, pkt);
        dec.decrypt_contents(&[], &mut out[3..]).unwrap();
        done += pkt;
    }
    let secs = t.elapsed().as_secs_f64();
    println!(
        "packet layer encrypt+decrypt: {:.0} MB/s per core (both directions' work), {:.2} ns/B",
        total as f64 / 1e6 / secs,
        secs * 1e9 / total as f64
    );

    // 4. Stream throughput: plain duplex vs ZKT2 over the same duplex.
    let chunk = vec![0xa5u8; 64 * 1024];
    let plain = rt.block_on(async {
        let (mut a, mut b) = duplex(1 << 20);
        let ch = chunk.clone();
        let w = tokio::spawn(async move {
            let mut sent = 0;
            while sent < total {
                a.write_all(&ch).await.unwrap();
                sent += ch.len();
            }
        });
        let t = Instant::now();
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0;
        while got < total {
            got += b.read(&mut buf).await.unwrap();
        }
        w.await.unwrap();
        t.elapsed().as_secs_f64()
    });
    let zkt2 = rt.block_on(async {
        let (a, mut b) = duplex(1 << 20);
        let c2 = cfg.clone();
        let resp = tokio::spawn(async move {
            let mut prefix = [0u8; SNIFF_LEN];
            b.read_exact(&mut prefix).await.unwrap();
            Zkt2Stream::respond(b, &prefix, &c2).await.unwrap()
        });
        let mut i = Zkt2Stream::initiate(a, &cfg).await.unwrap();
        let mut r = resp.await.unwrap();
        let ch = chunk.clone();
        let w = tokio::spawn(async move {
            let mut sent = 0;
            while sent < total {
                i.write_all(&ch).await.unwrap();
                sent += ch.len();
            }
            i.flush().await.unwrap();
        });
        let t = Instant::now();
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0;
        while got < total {
            got += r.read(&mut buf).await.unwrap();
        }
        w.await.unwrap();
        t.elapsed().as_secs_f64()
    });
    println!(
        "stream {} MB: plaintext duplex {:.0} MB/s, ZKT2 {:.0} MB/s (one core for both ends)",
        megabytes,
        total as f64 / 1e6 / plain,
        total as f64 / 1e6 / zkt2
    );
    println!(
        "wire overhead per 64 KiB write: {} B = {:.3}%; per 15,502 B tx message: 20 B = {:.3}%",
        kaspa_zkt2::cipher::PACKET_OVERHEAD,
        100.0 * kaspa_zkt2::cipher::PACKET_OVERHEAD as f64 / 65536.0,
        100.0 * 20.0 / 15502.0
    );
}
