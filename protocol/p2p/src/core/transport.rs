//! The byte-stream layer under the p2p HTTP/2 connection: plaintext (v1, protocol <= 10) or ZKT2
//! (BIP 324, spec 06 §3.1). tonic and every flow run unchanged on top of either.
//!
//! Responder (T-5): read the first 16 bytes; `PRI * HTTP/2.0\r\n` is a plaintext peer, anything
//! else is the start of a ZKT2 public key. Initiator (T-6): try ZKT2 first; a peer that answers
//! with an HTTP/2 server preface, or closes before sending a whole key, is a v10 node and may be
//! retried once in plaintext while `allow_v1_outbound` holds. Such an address is remembered as
//! `v1_only` for 24 h so the node does not show a "try v2, retry v1" pattern on every dial; an
//! address that completed a ZKT2 handshake once is `v2_capable` and is never retried in
//! plaintext (downgrade defence).

use kaspa_core::{debug, warn};
use kaspa_zkt2::{H2_PREFACE_PREFIX, HandshakeConfig, HandshakeError, SNIFF_LEN, Zkt2Stream, zkas_salt};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpSocket, TcpStream};
use tonic::transport::server::Connected;

/// How long a responder waits for the 16 sniff bytes and the whole ZKT2 handshake.
pub const RESPONDER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an initiator waits for the ZKT2 handshake before giving up (T-6: 5 s).
pub const INITIATOR_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// TCP connect timeout (unchanged from the plaintext dialer).
pub const TCP_CONNECT_TIMEOUT: Duration = Duration::from_millis(1_000);
/// How long a `v1_only` mark lasts (T-6).
pub const V1_ONLY_MARK: Duration = Duration::from_secs(24 * 60 * 60);
/// Concurrent inbound transport handshakes; the rest wait in the listen backlog.
pub const MAX_PENDING_TRANSPORT_HANDSHAKES: usize = 64;
/// Outbound TCP keepalive probe time (what the plaintext dialer set through tonic).
pub const TCP_KEEPALIVE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    /// Plaintext HTTP/2 (v1).
    V1,
    /// ZKT2 (BIP 324 under HTTP/2).
    V2,
}

impl std::fmt::Display for TransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TransportKind::V1 => "v1",
            TransportKind::V2 => "v2",
        })
    }
}

/// What a peer's connection runs on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportInfo {
    pub kind: TransportKind,
    /// The BIP 324 session id of a v2 connection (T-7).
    pub session_id: Option<[u8; 32]>,
}

impl TransportInfo {
    pub fn v1() -> Self {
        Self { kind: TransportKind::V1, session_id: None }
    }
}

/// Transport settings of a p2p adaptor.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Speak ZKT2 at all. False = plaintext only (the legacy constructors, and `--p2p-v1-only`).
    pub v2: bool,
    /// HKDF salt input: `config.network_name()`, e.g. `zkas-mainnet`.
    pub network_name: String,
    /// Accept plaintext inbound connections (rollout phases R1, R2).
    pub allow_v1_inbound: bool,
    /// Fall back to plaintext when a dialled peer turns out to be v1 (rollout phase R1).
    pub allow_v1_outbound: bool,
    /// Bind outbound sockets to this local IP (multi-homed hosts; a loopback devnet uses distinct
    /// 127.x addresses per node so peers see distinct source IPs).
    pub outbound_bind_ip: Option<IpAddr>,
    /// Upper bound of the uniformly drawn handshake garbage (BIP 324: 4,095).
    pub max_garbage: usize,
}

impl TransportConfig {
    /// Plaintext only: what every pre-v11 build spoke, and what external users of the library
    /// (explorer probes, Kaspa observers) keep getting from the legacy constructors.
    pub fn plaintext() -> Self {
        Self {
            v2: false,
            network_name: String::new(),
            allow_v1_inbound: true,
            allow_v1_outbound: true,
            outbound_bind_ip: None,
            max_garbage: kaspa_zkt2::stream::MAX_GARBAGE_LEN,
        }
    }

    /// Rollout phase R1: ZKT2 first, plaintext accepted and used as fallback.
    pub fn zkt2_opportunistic(network_name: String) -> Self {
        Self { v2: true, network_name, ..Self::plaintext() }
    }

    fn handshake_config(&self) -> HandshakeConfig {
        HandshakeConfig { salt: zkas_salt(&self.network_name), max_garbage: self.max_garbage }
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self::plaintext()
    }
}

/// A TCP stream with some already-read bytes put back in front (the responder's sniff).
pub struct PrefixedTcp {
    prefix: Vec<u8>,
    pos: usize,
    tcp: TcpStream,
}

impl AsyncRead for PrefixedTcp {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.pos < self.prefix.len() {
            let n = (self.prefix.len() - self.pos).min(buf.remaining());
            let start = self.pos;
            buf.put_slice(&self.prefix[start..start + n]);
            self.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.tcp).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedTcp {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tcp).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tcp).poll_shutdown(cx)
    }
}

/// One p2p connection's byte stream.
pub enum P2pConn {
    Plain(PrefixedTcp),
    V2(Box<Zkt2Stream<TcpStream>>),
}

/// Request extension carried to `message_stream` for inbound connections.
#[derive(Debug, Clone, Copy)]
pub struct P2pConnectInfo {
    pub remote: SocketAddr,
    pub transport: TransportInfo,
}

impl P2pConn {
    pub fn plain(tcp: TcpStream) -> Self {
        P2pConn::Plain(PrefixedTcp { prefix: Vec::new(), pos: 0, tcp })
    }

    fn tcp(&self) -> &TcpStream {
        match self {
            P2pConn::Plain(p) => &p.tcp,
            P2pConn::V2(s) => s.get_ref(),
        }
    }

    pub fn transport(&self) -> TransportInfo {
        match self {
            P2pConn::Plain(_) => TransportInfo::v1(),
            P2pConn::V2(s) => TransportInfo { kind: TransportKind::V2, session_id: Some(s.session_id()) },
        }
    }
}

impl Connected for P2pConn {
    type ConnectInfo = P2pConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        let remote = self.tcp().peer_addr().unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        P2pConnectInfo { remote, transport: self.transport() }
    }
}

impl AsyncRead for P2pConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            P2pConn::Plain(p) => Pin::new(p).poll_read(cx, buf),
            P2pConn::V2(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for P2pConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            P2pConn::Plain(p) => Pin::new(p).poll_write(cx, buf),
            P2pConn::V2(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            P2pConn::Plain(p) => Pin::new(p).poll_flush(cx),
            P2pConn::V2(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            P2pConn::Plain(p) => Pin::new(p).poll_shutdown(cx),
            P2pConn::V2(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Responder side: decides plaintext vs ZKT2 from the first bytes and completes the handshake.
/// `Ok(None)` means the connection was dropped on purpose (plaintext while v1 inbound is off).
pub async fn accept(mut tcp: TcpStream, config: &TransportConfig) -> Result<Option<P2pConn>, HandshakeError> {
    let _ = tcp.set_nodelay(true);
    if !config.v2 {
        return Ok(Some(P2pConn::plain(tcp)));
    }
    let mut prefix = [0u8; SNIFF_LEN];
    tcp.read_exact(&mut prefix).await?;
    if &prefix == H2_PREFACE_PREFIX {
        if !config.allow_v1_inbound {
            return Ok(None);
        }
        return Ok(Some(P2pConn::Plain(PrefixedTcp { prefix: prefix.to_vec(), pos: 0, tcp })));
    }
    let stream = Zkt2Stream::respond(tcp, &prefix, &config.handshake_config()).await?;
    Ok(Some(P2pConn::V2(Box::new(stream))))
}

async fn tcp_connect(addr: SocketAddr, bind: Option<IpAddr>) -> io::Result<TcpStream> {
    let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
    if let Some(ip) = bind
        && ip.is_ipv4() == addr.is_ipv4()
    {
        socket.bind(SocketAddr::new(ip, 0))?;
    }
    let tcp = tokio::time::timeout(TCP_CONNECT_TIMEOUT, socket.connect(addr))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tcp connect timed out"))??;
    let _ = tcp.set_nodelay(true);
    // The plaintext dialer used tonic's `tcp_keepalive(10 s)`; keep the same probe time.
    let _ = socket2::SockRef::from(&tcp).set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(TCP_KEEPALIVE));
    Ok(tcp)
}

/// Per-address memory of what transport a peer speaks (T-6). In memory only: a restart forgets
/// it, so the downgrade defence holds per process lifetime.
#[derive(Default)]
pub struct TransportMarks {
    v1_only: HashMap<SocketAddr, Instant>,
    v2_capable: HashSet<SocketAddr>,
}

impl TransportMarks {
    fn is_v1_only(&mut self, addr: &SocketAddr) -> bool {
        match self.v1_only.get(addr) {
            Some(at) if at.elapsed() < V1_ONLY_MARK => true,
            Some(_) => {
                self.v1_only.remove(addr);
                false
            }
            None => false,
        }
    }
}

/// Initiator side: dial `addr`, ZKT2 first, plaintext fallback per T-6.
pub async fn dial(addr: SocketAddr, config: &TransportConfig, marks: &Arc<Mutex<TransportMarks>>) -> io::Result<P2pConn> {
    if !config.v2 {
        return Ok(P2pConn::plain(tcp_connect(addr, config.outbound_bind_ip).await?));
    }
    let v1_only = marks.lock().is_v1_only(&addr);
    if v1_only && config.allow_v1_outbound {
        return Ok(P2pConn::plain(tcp_connect(addr, config.outbound_bind_ip).await?));
    }
    let tcp = tcp_connect(addr, config.outbound_bind_ip).await?;
    match tokio::time::timeout(INITIATOR_HANDSHAKE_TIMEOUT, Zkt2Stream::initiate(tcp, &config.handshake_config())).await {
        Ok(Ok(stream)) => {
            let mut m = marks.lock();
            m.v2_capable.insert(addr);
            m.v1_only.remove(&addr);
            Ok(P2pConn::V2(Box::new(stream)))
        }
        Ok(Err(err @ (HandshakeError::LegacyPeer | HandshakeError::PeerClosed(_)))) => {
            let downgrade_refused = marks.lock().v2_capable.contains(&addr);
            if downgrade_refused {
                warn!("P2P, {addr} completed a ZKT2 handshake before and now refuses one ({err}); not retrying in plaintext");
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, err));
            }
            if !config.allow_v1_outbound {
                return Err(io::Error::new(io::ErrorKind::ConnectionRefused, err));
            }
            debug!("P2P, {addr} is a plaintext (v10) peer ({err}); retrying in v1 and remembering it for 24 h");
            marks.lock().v1_only.insert(addr, Instant::now());
            Ok(P2pConn::plain(tcp_connect(addr, config.outbound_bind_ip).await?))
        }
        Ok(Err(err)) => Err(io::Error::other(err)),
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "ZKT2 handshake timed out")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    async fn listener() -> (TcpListener, SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    #[tokio::test]
    async fn v2_dial_to_v2_accept_and_the_session_ids_agree() {
        let (l, addr) = listener().await;
        let cfg = TransportConfig::zkt2_opportunistic("zkas-devnet".into());
        let c2 = cfg.clone();
        let srv = tokio::spawn(async move { accept(l.accept().await.unwrap().0, &c2).await.unwrap().unwrap() });
        let marks = Arc::new(Mutex::new(TransportMarks::default()));
        let mut client = dial(addr, &cfg, &marks).await.unwrap();
        let mut server = srv.await.unwrap();
        assert_eq!(client.transport().kind, TransportKind::V2);
        assert_eq!(client.transport().session_id, server.transport().session_id);
        client.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 24];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        assert!(marks.lock().v2_capable.contains(&addr));
    }

    #[tokio::test]
    async fn a_plaintext_client_is_served_in_plaintext_with_its_bytes_intact() {
        let (l, addr) = listener().await;
        let cfg = TransportConfig::zkt2_opportunistic("zkas-devnet".into());
        let srv = tokio::spawn(async move { accept(l.accept().await.unwrap().0, &cfg).await.unwrap().unwrap() });
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nrest").await.unwrap();
        let mut server = srv.await.unwrap();
        assert_eq!(server.transport().kind, TransportKind::V1);
        let mut got = [0u8; 28];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\nrest");
    }

    #[tokio::test]
    async fn plaintext_inbound_is_refused_when_v1_is_off() {
        let (l, addr) = listener().await;
        let cfg = TransportConfig { allow_v1_inbound: false, ..TransportConfig::zkt2_opportunistic("zkas-devnet".into()) };
        let srv = tokio::spawn(async move { accept(l.accept().await.unwrap().0, &cfg).await.unwrap() });
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        tcp.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        assert!(srv.await.unwrap().is_none());
    }

    /// A v10 server: answers any connection with an h2 SETTINGS frame and expects the preface.
    async fn fake_v10_server(l: TcpListener, conns: usize) -> Vec<Vec<u8>> {
        let mut firsts = Vec::new();
        for _ in 0..conns {
            let (mut s, _) = l.accept().await.unwrap();
            s.write_all(&[0, 0, 6, 0x04, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100]).await.unwrap();
            let mut buf = vec![0u8; 24];
            let _ = s.read_exact(&mut buf).await;
            firsts.push(buf);
        }
        firsts
    }

    #[tokio::test]
    async fn a_v10_peer_gets_one_plaintext_retry_and_is_then_dialled_in_v1_directly() {
        let (l, addr) = listener().await;
        let srv = tokio::spawn(fake_v10_server(l, 3));
        let cfg = TransportConfig::zkt2_opportunistic("zkas-devnet".into());
        let marks = Arc::new(Mutex::new(TransportMarks::default()));
        let mut c = dial(addr, &cfg, &marks).await.unwrap();
        assert_eq!(c.transport().kind, TransportKind::V1);
        c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        // Second dial: marked v1_only, so no ZKT2 attempt.
        let mut c = dial(addr, &cfg, &marks).await.unwrap();
        assert_eq!(c.transport().kind, TransportKind::V1);
        c.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").await.unwrap();
        drop(c);
        let firsts = srv.await.unwrap();
        // Connection 1 got our ZKT2 key (not a preface), 2 and 3 got plaintext prefaces.
        assert_ne!(&firsts[0][..16], H2_PREFACE_PREFIX);
        assert_eq!(&firsts[1][..16], H2_PREFACE_PREFIX);
        assert_eq!(&firsts[2][..16], H2_PREFACE_PREFIX);
    }

    #[tokio::test]
    async fn a_known_v2_peer_is_never_downgraded() {
        let (l, addr) = listener().await;
        let srv = tokio::spawn(fake_v10_server(l, 1));
        let cfg = TransportConfig::zkt2_opportunistic("zkas-devnet".into());
        let marks = Arc::new(Mutex::new(TransportMarks::default()));
        marks.lock().v2_capable.insert(addr);
        let err = dial(addr, &cfg, &marks).await.err().expect("must refuse the downgrade");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        srv.abort();
    }

    #[tokio::test]
    async fn no_fallback_when_v1_outbound_is_off() {
        let (l, addr) = listener().await;
        let srv = tokio::spawn(fake_v10_server(l, 1));
        let cfg = TransportConfig { allow_v1_outbound: false, ..TransportConfig::zkt2_opportunistic("zkas-devnet".into()) };
        let marks = Arc::new(Mutex::new(TransportMarks::default()));
        assert!(dial(addr, &cfg, &marks).await.is_err());
        srv.abort();
    }
}
