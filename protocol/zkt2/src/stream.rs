//! The ZKT2 handshake (BIP 324 §"Handshake") and the encrypted duplex byte stream it yields.
//!
//! ZKT2 does not map p2p messages to packets the way Bitcoin's v2 transport does. It carries the
//! HTTP/2 byte stream that tonic already speaks: every `poll_write` becomes one packet (split at
//! [`MAX_PACKET_CONTENTS`]), and the reader reassembles packet contents into a byte stream. gRPC,
//! the router and every flow run unchanged on top.

use crate::cipher::{
    AuthError, HEADER_LEN, LENGTH_FIELD_LEN, PACKET_OVERHEAD, PacketDecryptor, PacketEncryptor, SessionKeys, TAG_LEN,
};
use rand::{Rng, RngCore};
use secp256k1::SecretKey;
use secp256k1::ellswift::{ElligatorSwift, ElligatorSwiftParty};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Bytes of an ElligatorSwift-encoded public key.
pub const ELLSWIFT_LEN: usize = 64;
/// Garbage terminator length.
pub const GARBAGE_TERMINATOR_LEN: usize = 16;
/// Maximum garbage a peer may send before its terminator (BIP 324).
pub const MAX_GARBAGE_LEN: usize = 4095;
/// Largest packet contents ZKT2 sends or accepts (spec 06 T-3). Larger h2 writes are split.
pub const MAX_PACKET_CONTENTS: usize = 65_536;
/// The first 16 bytes of the HTTP/2 client connection preface (RFC 9113 §3.4). A responder that
/// reads exactly these bytes is talking to a plaintext (v10) peer (spec 06 T-5).
pub const H2_PREFACE_PREFIX: &[u8; 16] = b"PRI * HTTP/2.0\r\n";
/// How many leading bytes a responder reads to tell ZKT2 from plaintext HTTP/2.
pub const SNIFF_LEN: usize = H2_PREFACE_PREFIX.len();

/// Which end of the TCP connection this side is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("ZKT2 I/O error: {0}")]
    Io(#[from] io::Error),
    /// The responder answered with an HTTP/2 server preface: it is a plaintext (v10) node.
    #[error("peer answered in plaintext HTTP/2 (a v10 node)")]
    LegacyPeer,
    /// The peer closed the connection before sending a whole public key.
    #[error("peer closed the connection after {0} handshake bytes")]
    PeerClosed(usize),
    #[error("peer sent no garbage terminator within {MAX_GARBAGE_LEN} bytes")]
    NoGarbageTerminator,
    #[error("peer sent a packet larger than {MAX_PACKET_CONTENTS} bytes")]
    OversizedPacket,
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("the responder must be handed at most {ELLSWIFT_LEN} already-read bytes")]
    BadPrefix,
}

/// Handshake parameters.
#[derive(Clone, Debug)]
pub struct HandshakeConfig {
    /// HKDF salt; [`crate::cipher::zkas_salt`] for ZKas networks.
    pub salt: Vec<u8>,
    /// Upper bound (inclusive) of the uniformly drawn garbage length. BIP 324 allows 0..=4095.
    pub max_garbage: usize,
}

impl HandshakeConfig {
    pub fn new(salt: Vec<u8>) -> Self {
        Self { salt, max_garbage: MAX_GARBAGE_LEN }
    }
}

/// A fresh secp256k1 key and its ElligatorSwift encoding. The initiator re-draws the key if its
/// encoding happens to begin with the HTTP/2 preface (probability 2^-128), so the responder's
/// sniff is total (spec 06 T-5).
fn fresh_key(role: Role) -> (SecretKey, ElligatorSwift) {
    let mut rng = rand::thread_rng();
    loop {
        let mut sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut sk_bytes);
        let Ok(sk) = SecretKey::from_slice(&sk_bytes) else { continue };
        let mut aux = [0u8; 32];
        rng.fill_bytes(&mut aux);
        let es = ElligatorSwift::from_seckey(&**secp256k1::SECP256K1, sk, Some(aux));
        if role == Role::Initiator && es.to_array()[..SNIFF_LEN] == H2_PREFACE_PREFIX[..] {
            continue;
        }
        return (sk, es);
    }
}

/// The BIP 324 ECDH secret for this side.
pub fn ecdh_secret(ours: &ElligatorSwift, theirs: &ElligatorSwift, sk: SecretKey, role: Role) -> [u8; 32] {
    let secret = match role {
        Role::Initiator => ElligatorSwift::shared_secret(*ours, *theirs, sk, ElligatorSwiftParty::A, None),
        Role::Responder => ElligatorSwift::shared_secret(*theirs, *ours, sk, ElligatorSwiftParty::B, None),
    };
    secret.to_secret_bytes()
}

/// Whether bytes a dialled peer sent look like an HTTP/2 server's first frame (a SETTINGS frame on
/// stream 0). A ZKT2 responder sends a uniformly random public key, which matches with
/// probability 2^-40.
pub fn looks_like_h2_server_preface(bytes: &[u8]) -> bool {
    bytes.len() >= 9 && bytes[3] == 0x04 && bytes[5..9] == [0, 0, 0, 0]
}

/// An established ZKT2 connection over `S`.
pub struct Zkt2Stream<S> {
    io: S,
    session_id: [u8; 32],
    enc: PacketEncryptor,
    dec: PacketDecryptor,
    /// AAD for the first received packet (the peer's garbage); taken once.
    recv_aad: Option<Vec<u8>>,

    // read side
    rbuf: Vec<u8>,
    rpos: usize,
    pending_len: Option<usize>,
    plain: Vec<u8>,
    plain_pos: usize,

    // write side
    wbuf: Vec<u8>,
    wpos: usize,

    bytes_sent: u64,
    bytes_received: u64,
}

impl<S> std::fmt::Debug for Zkt2Stream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Zkt2Stream").field("session_id", &self.session_id).finish_non_exhaustive()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> Zkt2Stream<S> {
    /// Runs the initiator side of the handshake on a freshly connected `io`.
    pub async fn initiate(io: S, config: &HandshakeConfig) -> Result<Self, HandshakeError> {
        Self::handshake(io, Role::Initiator, &[], config).await
    }

    /// Runs the responder side. `prefix` are bytes the caller already read from `io` (the sniff),
    /// which are the start of the initiator's public key.
    pub async fn respond(io: S, prefix: &[u8], config: &HandshakeConfig) -> Result<Self, HandshakeError> {
        if prefix.len() > ELLSWIFT_LEN {
            return Err(HandshakeError::BadPrefix);
        }
        Self::handshake(io, Role::Responder, prefix, config).await
    }

    async fn handshake(mut io: S, role: Role, prefix: &[u8], config: &HandshakeConfig) -> Result<Self, HandshakeError> {
        let (sk, ours) = fresh_key(role);
        let garbage_len = rand::thread_rng().gen_range(0..=config.max_garbage.min(MAX_GARBAGE_LEN));
        let mut sent_garbage = vec![0u8; garbage_len];
        rand::thread_rng().fill_bytes(&mut sent_garbage);

        let mut rbuf: Vec<u8> = prefix.to_vec();

        if role == Role::Initiator {
            let mut first = Vec::with_capacity(ELLSWIFT_LEN + garbage_len);
            first.extend_from_slice(&ours.to_array());
            first.extend_from_slice(&sent_garbage);
            io.write_all(&first).await?;
            io.flush().await?;
        }

        // Their public key.
        while rbuf.len() < ELLSWIFT_LEN {
            let mut chunk = [0u8; 4096];
            let n = io.read(&mut chunk).await?;
            if n == 0 {
                if role == Role::Initiator && looks_like_h2_server_preface(&rbuf) {
                    return Err(HandshakeError::LegacyPeer);
                }
                return Err(HandshakeError::PeerClosed(rbuf.len()));
            }
            rbuf.extend_from_slice(&chunk[..n]);
            if role == Role::Initiator && looks_like_h2_server_preface(&rbuf) {
                return Err(HandshakeError::LegacyPeer);
            }
        }
        let mut theirs_bytes = [0u8; ELLSWIFT_LEN];
        theirs_bytes.copy_from_slice(&rbuf[..ELLSWIFT_LEN]);
        let theirs = ElligatorSwift::from_array(theirs_bytes);
        let mut rpos = ELLSWIFT_LEN;

        let keys = SessionKeys::derive(&ecdh_secret(&ours, &theirs, sk, role), &config.salt);
        let (send_l, send_p, recv_l, recv_p, send_term, recv_term) = match role {
            Role::Initiator => (
                keys.initiator_l,
                keys.initiator_p,
                keys.responder_l,
                keys.responder_p,
                keys.initiator_garbage_terminator,
                keys.responder_garbage_terminator,
            ),
            Role::Responder => (
                keys.responder_l,
                keys.responder_p,
                keys.initiator_l,
                keys.initiator_p,
                keys.responder_garbage_terminator,
                keys.initiator_garbage_terminator,
            ),
        };
        let mut enc = PacketEncryptor::new(send_l, send_p);
        let dec = PacketDecryptor::new(recv_l, recv_p);

        // Our (responder: key + garbage +) terminator + version packet. The version packet is the
        // first packet in this direction, so it authenticates our garbage as AAD.
        let mut out = Vec::with_capacity(ELLSWIFT_LEN + garbage_len + GARBAGE_TERMINATOR_LEN + PACKET_OVERHEAD);
        if role == Role::Responder {
            out.extend_from_slice(&ours.to_array());
            out.extend_from_slice(&sent_garbage);
        }
        out.extend_from_slice(&send_term);
        enc.encrypt_packet(&[], &sent_garbage, false, &mut out);
        io.write_all(&out).await?;
        io.flush().await?;

        // Skip their garbage up to the terminator.
        let garbage_start = rpos;
        let recv_garbage = loop {
            let have = &rbuf[garbage_start..];
            if let Some(i) = have.windows(GARBAGE_TERMINATOR_LEN).position(|w| w == recv_term) {
                if i > MAX_GARBAGE_LEN {
                    return Err(HandshakeError::NoGarbageTerminator);
                }
                let garbage = have[..i].to_vec();
                rpos = garbage_start + i + GARBAGE_TERMINATOR_LEN;
                break garbage;
            }
            if have.len() >= MAX_GARBAGE_LEN + GARBAGE_TERMINATOR_LEN {
                return Err(HandshakeError::NoGarbageTerminator);
            }
            let mut chunk = [0u8; 4096];
            let n = io.read(&mut chunk).await?;
            if n == 0 {
                return Err(HandshakeError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            rbuf.extend_from_slice(&chunk[..n]);
        };

        let mut stream = Self {
            io,
            session_id: keys.session_id,
            enc,
            dec,
            recv_aad: Some(recv_garbage),
            rbuf,
            rpos,
            pending_len: None,
            plain: Vec::new(),
            plain_pos: 0,
            wbuf: Vec::new(),
            wpos: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };
        // Their version packet (after any decoys). Its contents are reserved and ignored (T-3).
        loop {
            let packet = std::future::poll_fn(|cx| stream.poll_next_packet(cx)).await?;
            match packet {
                Some(false) => break,
                Some(true) => continue,
                None => return Err(HandshakeError::Io(io::ErrorKind::UnexpectedEof.into())),
            }
        }
        // The version packet's contents are not part of the byte stream.
        stream.plain.clear();
        stream.plain_pos = 0;
        Ok(stream)
    }
}

impl<S> Zkt2Stream<S> {
    /// The BIP 324 session id; operators compare it out of band (spec 06 T-7) and the pinned-key
    /// authentication (T-8) signs it.
    pub fn session_id(&self) -> [u8; 32] {
        self.session_id
    }

    pub fn get_ref(&self) -> &S {
        &self.io
    }

    /// Ciphertext bytes written to / read from the underlying stream after the handshake.
    pub fn wire_counters(&self) -> (u64, u64) {
        (self.bytes_sent, self.bytes_received)
    }

    /// Queues a decoy packet of `len` random bytes (ignore bit set); the peer discards it (T-4).
    pub fn queue_decoy(&mut self, len: usize) {
        let mut contents = vec![0u8; len.min(MAX_PACKET_CONTENTS)];
        rand::thread_rng().fill_bytes(&mut contents);
        self.enc.encrypt_packet(&contents, &[], true, &mut self.wbuf);
    }
}

impl<S: AsyncRead + Unpin> Zkt2Stream<S> {
    /// Reads and decrypts the next packet into `self.plain`. Returns `Some(ignore)` for a packet,
    /// `None` on a clean EOF at a packet boundary.
    fn poll_next_packet(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<bool>, HandshakeError>> {
        loop {
            let avail = self.rbuf.len() - self.rpos;
            if self.pending_len.is_none() && avail >= LENGTH_FIELD_LEN {
                let mut field = [0u8; LENGTH_FIELD_LEN];
                field.copy_from_slice(&self.rbuf[self.rpos..self.rpos + LENGTH_FIELD_LEN]);
                let len = self.dec.decrypt_length(field);
                if len > MAX_PACKET_CONTENTS {
                    return Poll::Ready(Err(HandshakeError::OversizedPacket));
                }
                self.rpos += LENGTH_FIELD_LEN;
                self.pending_len = Some(len);
                continue;
            }
            if let Some(len) = self.pending_len {
                let need = HEADER_LEN + len + TAG_LEN;
                if avail >= need {
                    let aad = self.recv_aad.take().unwrap_or_default();
                    let start = self.rpos;
                    let ignore = self.dec.decrypt_contents(&aad, &mut self.rbuf[start..start + need])?;
                    self.pending_len = None;
                    self.rpos += need;
                    if !ignore {
                        self.plain.clear();
                        self.plain.extend_from_slice(&self.rbuf[start + HEADER_LEN..start + HEADER_LEN + len]);
                        self.plain_pos = 0;
                    }
                    self.compact();
                    return Poll::Ready(Ok(Some(ignore)));
                }
            }
            // Need more ciphertext.
            self.compact();
            let mut chunk = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut self.io).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                if self.pending_len.is_some() || self.rbuf.len() > self.rpos {
                    return Poll::Ready(Err(HandshakeError::Io(io::ErrorKind::UnexpectedEof.into())));
                }
                return Poll::Ready(Ok(None));
            }
            self.bytes_received += n as u64;
            self.rbuf.extend_from_slice(rb.filled());
        }
    }

    fn compact(&mut self) {
        if self.rpos > 0 && (self.rpos == self.rbuf.len() || self.rpos > 64 * 1024) {
            self.rbuf.drain(..self.rpos);
            self.rpos = 0;
        }
    }
}

fn to_io(e: HandshakeError) -> io::Error {
    match e {
        HandshakeError::Io(e) => e,
        other => io::Error::new(io::ErrorKind::InvalidData, other),
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Zkt2Stream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if this.plain_pos < this.plain.len() {
                let n = (this.plain.len() - this.plain_pos).min(buf.remaining());
                buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            match ready!(this.poll_next_packet(cx)).map_err(to_io)? {
                None => return Poll::Ready(Ok(())), // EOF
                Some(_) => continue,                // decoys leave `plain` empty and loop
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> Zkt2Stream<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.wbuf[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
            self.bytes_sent += n as u64;
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Zkt2Stream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        // Backpressure: accept new plaintext only once the previous packet left.
        ready!(this.poll_drain(cx))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_PACKET_CONTENTS);
        this.enc.encrypt_packet(&data[..n], &[], false, &mut this.wbuf);
        // Start sending right away; whatever does not fit now goes on the next write or flush.
        let _ = this.poll_drain(cx)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::zkas_salt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn cfg() -> HandshakeConfig {
        HandshakeConfig::new(zkas_salt("zkas-devnet"))
    }

    async fn pair() -> (Zkt2Stream<tokio::io::DuplexStream>, Zkt2Stream<tokio::io::DuplexStream>) {
        let (a, mut b) = duplex(1 << 20);
        let c = cfg();
        let c2 = c.clone();
        let resp = tokio::spawn(async move {
            let mut prefix = [0u8; SNIFF_LEN];
            b.read_exact(&mut prefix).await.unwrap();
            assert_ne!(&prefix, H2_PREFACE_PREFIX);
            Zkt2Stream::respond(b, &prefix, &c2).await.unwrap()
        });
        let init = Zkt2Stream::initiate(a, &c).await.unwrap();
        (init, resp.await.unwrap())
    }

    #[tokio::test]
    async fn handshake_agrees_and_carries_a_byte_stream_both_ways() {
        let (mut i, mut r) = pair().await;
        assert_eq!(i.session_id(), r.session_id());
        // Bigger than one packet, so it is split, and the reader reassembles it.
        let big: Vec<u8> = (0..200_000u32).map(|x| (x % 253) as u8).collect();
        let big2 = big.clone();
        let w = tokio::spawn(async move {
            i.write_all(&big2).await.unwrap();
            i.flush().await.unwrap();
            i
        });
        let mut got = vec![0u8; big.len()];
        r.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
        let mut i = w.await.unwrap();
        r.write_all(b"pong").await.unwrap();
        r.flush().await.unwrap();
        let mut p = [0u8; 4];
        i.read_exact(&mut p).await.unwrap();
        assert_eq!(&p, b"pong");
    }

    #[tokio::test]
    async fn decoys_are_discarded_and_rekey_is_transparent() {
        let (mut i, mut r) = pair().await;
        // 3 rekey intervals' worth of packets with decoys mixed in.
        let w = tokio::spawn(async move {
            for k in 0..700u32 {
                if k % 3 == 0 {
                    i.queue_decoy(17);
                }
                i.write_all(&k.to_le_bytes()).await.unwrap();
                i.flush().await.unwrap();
            }
            i
        });
        for k in 0..700u32 {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await.unwrap();
            assert_eq!(u32::from_le_bytes(b), k);
        }
        w.await.unwrap();
    }

    #[tokio::test]
    async fn a_flipped_ciphertext_byte_kills_the_stream() {
        let (a, b) = duplex(1 << 20);
        // A man in the middle relaying with one byte flipped after the handshake.
        let (mitm_i, mut mitm_o) = duplex(1 << 20);
        let c = cfg();
        let c2 = c.clone();
        let resp = tokio::spawn(async move {
            let mut prefix = [0u8; SNIFF_LEN];
            mitm_o.read_exact(&mut prefix).await.unwrap();
            Zkt2Stream::respond(mitm_o, &prefix, &c2).await
        });
        // Relay a <-> mitm_i, flipping byte 3000 of the initiator's stream.
        let (mut ar, mut aw) = tokio::io::split(b);
        let (mut mr, mut mw) = tokio::io::split(mitm_i);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut total = 0usize;
            loop {
                let n = ar.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                for (k, byte) in buf[..n].iter_mut().enumerate() {
                    if total + k == 3000 + 5000 {
                        *byte ^= 0x40;
                    }
                }
                total += n;
                if mw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut mr, &mut aw).await;
        });
        let mut i = Zkt2Stream::initiate(a, &HandshakeConfig { max_garbage: 0, ..c }).await.unwrap();
        let mut r = resp.await.unwrap().unwrap();
        let data = vec![5u8; 20_000];
        i.write_all(&data).await.unwrap();
        i.flush().await.unwrap();
        let mut got = vec![0u8; data.len()];
        let err = r.read_exact(&mut got).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    #[tokio::test]
    async fn the_initiator_recognises_a_plaintext_http2_server() {
        // What a v10 node's h2 server sends first: a SETTINGS frame on stream 0, then GOAWAY.
        let (a, mut b) = duplex(1 << 16);
        tokio::spawn(async move {
            let settings = [0u8, 0, 12, 0x04, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100, 0, 4, 0, 0x10, 0, 0];
            b.write_all(&settings).await.unwrap();
            let mut sink = [0u8; 128];
            let _ = b.read(&mut sink).await;
            drop(b);
        });
        let err = Zkt2Stream::initiate(a, &cfg()).await.unwrap_err();
        assert!(matches!(err, HandshakeError::LegacyPeer), "{err}");
    }

    #[tokio::test]
    async fn a_silent_close_is_reported_with_the_byte_count() {
        let (a, b) = duplex(1 << 16);
        drop(b);
        let err = Zkt2Stream::initiate(a, &cfg()).await.unwrap_err();
        assert!(matches!(err, HandshakeError::PeerClosed(0) | HandshakeError::Io(_)), "{err}");
    }

    #[tokio::test]
    async fn different_salts_do_not_interoperate() {
        let (a, mut b) = duplex(1 << 20);
        let resp = tokio::spawn(async move {
            let mut prefix = [0u8; SNIFF_LEN];
            b.read_exact(&mut prefix).await.unwrap();
            Zkt2Stream::respond(b, &prefix, &HandshakeConfig::new(zkas_salt("zkas-mainnet"))).await
        });
        let init = tokio::time::timeout(std::time::Duration::from_secs(5), Zkt2Stream::initiate(a, &cfg())).await;
        // Each side derives different terminators, so neither finds the other's within 4 KiB.
        let r = resp.await.unwrap();
        assert!(r.is_err());
        assert!(matches!(init, Ok(Err(_)) | Err(_)));
    }

    #[test]
    fn fresh_initiator_keys_never_start_with_the_h2_preface() {
        for _ in 0..64 {
            let (_, es) = fresh_key(Role::Initiator);
            assert_ne!(&es.to_array()[..SNIFF_LEN], H2_PREFACE_PREFIX);
        }
    }

    #[test]
    fn h2_preface_detection() {
        assert!(looks_like_h2_server_preface(&[0, 0, 0, 4, 0, 0, 0, 0, 0]));
        assert!(looks_like_h2_server_preface(&[0, 0, 0, 4, 1, 0, 0, 0, 0, 9]));
        assert!(!looks_like_h2_server_preface(&[0, 0, 0, 4, 0, 0, 0, 0]));
        assert!(!looks_like_h2_server_preface(&[0, 0, 0, 1, 0, 0, 0, 0, 0]));
    }
}
