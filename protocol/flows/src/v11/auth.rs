//! Optional pinned-key authentication of a ZKT2 connection (spec 06 T-8).
//!
//! BIP 324 is unauthenticated: an active man in the middle between two nodes that never met can
//! run two sessions. For operator-to-operator links (pool <-> relay, seed <-> seed) a node may
//! pin the peer's long-term BIP 340 key. The pinning side sends a commitment to
//! `(session_id, pubkey)`; only a peer holding exactly that key recognises it and answers with a
//! Schnorr signature over the session id. Any other peer, including an unpinned honest one,
//! answers nothing and stays connected, so the request never reveals which key is pinned and a
//! node's key is never shown to a peer that does not already know it. A MITM cannot answer: the
//! session ids of its two sessions differ, and it cannot sign for the pinned key.

use crate::{flow_context::FlowContext, flow_trait::Flow};
use kaspa_core::{info, warn};
use kaspa_p2p_lib::{
    IncomingRoute, Router,
    common::ProtocolError,
    make_message,
    pb::{AuthRequestMessage, AuthResponseMessage, kaspad_message::Payload},
};
use secp256k1::{Keypair, Message, SECP256K1, XOnlyPublicKey, schnorr::Signature};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

/// How long a pinning side waits for the signature (T-8: 10 s).
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(10);

pub fn auth_commit(session_id: &[u8; 32], xonly: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"zkas-p2p-auth-req");
    h.update(session_id);
    h.update(xonly);
    h.finalize().into()
}

pub fn auth_digest(session_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"zkas-p2p-auth");
    h.update(session_id);
    h.finalize().into()
}

/// The pinned side: a signature if `commit` names our key on this session, else nothing.
pub fn answer_auth_request(keypair: &Keypair, session_id: &[u8; 32], commit: &[u8]) -> Option<[u8; 64]> {
    let xonly = keypair.x_only_public_key().0.serialize();
    if commit != auth_commit(session_id, &xonly) {
        return None;
    }
    let sig = SECP256K1.sign_schnorr(&Message::from_digest(auth_digest(session_id)), keypair);
    Some(sig.serialize())
}

/// The pinning side: whether `sig` proves the pinned key on this session.
pub fn verify_auth_response(pinned: &[u8; 32], session_id: &[u8; 32], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (XOnlyPublicKey::from_slice(pinned), Signature::from_slice(sig)) else { return false };
    SECP256K1.verify_schnorr(&sig, &Message::from_digest(auth_digest(session_id)), &pk).is_ok()
}

pub struct AuthFlow {
    ctx: FlowContext,
    router: Arc<Router>,
    incoming_route: IncomingRoute,
}

#[async_trait::async_trait]
impl Flow for AuthFlow {
    fn router(&self) -> Option<Arc<Router>> {
        Some(self.router.clone())
    }

    async fn start(&mut self) -> Result<(), ProtocolError> {
        self.start_impl().await
    }
}

impl AuthFlow {
    pub fn new(ctx: FlowContext, router: Arc<Router>, incoming_route: IncomingRoute) -> Self {
        Self { ctx, router, incoming_route }
    }

    async fn start_impl(&mut self) -> Result<(), ProtocolError> {
        let session = self.router.transport().session_id;
        let pin = if self.router.is_outbound() { self.ctx.pinned_key_for(self.router.net_address()) } else { None };
        let mut deadline = None;
        if let Some(pk) = pin {
            let Some(sid) = session else {
                warn!("P2P, pinned peer {} was reached over plaintext: possible downgrade by a man in the middle; disconnecting", self.router);
                return Err(ProtocolError::OtherOwned(format!("pinned peer {} reached without ZKT2", self.router)));
            };
            self.router
                .enqueue(make_message!(Payload::AuthRequest, AuthRequestMessage { commit: auth_commit(&sid, &pk).to_vec() }))
                .await?;
            deadline = Some(tokio::time::Instant::now() + AUTH_TIMEOUT);
        }
        let mut answered = false;
        loop {
            let msg = match deadline {
                Some(d) => match tokio::time::timeout_at(d, self.incoming_route.recv()).await {
                    Ok(m) => m,
                    Err(_) => {
                        warn!("P2P, pinned peer {} did not prove its key within 10 s: possible man in the middle; disconnecting", self.router);
                        return Err(ProtocolError::OtherOwned(format!("pinned peer {} failed authentication", self.router)));
                    }
                },
                None => self.incoming_route.recv().await,
            };
            let Some(msg) = msg else { return Err(ProtocolError::ConnectionClosed) };
            match msg.payload {
                Some(Payload::AuthRequest(req)) => {
                    // One answer per connection; a non-match is silence, never a disconnect.
                    if answered {
                        continue;
                    }
                    answered = true;
                    if let (Some(keypair), Some(sid)) = (self.ctx.auth_keypair(), session)
                        && let Some(sig) = answer_auth_request(&keypair, &sid, &req.commit)
                    {
                        self.router.enqueue(make_message!(Payload::AuthResponse, AuthResponseMessage { sig: sig.to_vec() })).await?;
                    }
                }
                Some(Payload::AuthResponse(resp)) => {
                    let (Some(pk), Some(sid)) = (pin, session) else { continue };
                    if deadline.is_none() {
                        continue;
                    }
                    if verify_auth_response(&pk, &sid, &resp.sig) {
                        info!("P2P, pinned peer {} authenticated (session {})", self.router, faster_session(&sid));
                        deadline = None;
                    } else {
                        warn!("P2P, pinned peer {} sent a bad signature: possible man in the middle; disconnecting", self.router);
                        return Err(ProtocolError::OtherOwned(format!("pinned peer {} failed authentication", self.router)));
                    }
                }
                _ => {}
            }
        }
    }
}

fn faster_session(sid: &[u8; 32]) -> String {
    hex::encode(&sid[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::SecretKey;

    fn kp(b: u8) -> Keypair {
        Keypair::from_secret_key(&**SECP256K1, &SecretKey::from_slice(&[b; 32]).unwrap())
    }

    #[test]
    fn the_pinned_key_answers_and_verifies() {
        let k = kp(7);
        let sid = [3u8; 32];
        let pk = k.x_only_public_key().0.serialize();
        let sig = answer_auth_request(&k, &sid, &auth_commit(&sid, &pk)).expect("matching commit is answered");
        assert!(verify_auth_response(&pk, &sid, &sig));
    }

    #[test]
    fn another_key_stays_silent() {
        let sid = [3u8; 32];
        let pinned = kp(7).x_only_public_key().0.serialize();
        assert!(answer_auth_request(&kp(8), &sid, &auth_commit(&sid, &pinned)).is_none());
    }

    #[test]
    fn a_man_in_the_middle_cannot_relay_the_answer() {
        // The MITM runs two sessions with different ids; a signature over one fails on the other.
        let k = kp(7);
        let pk = k.x_only_public_key().0.serialize();
        let (sid_a, sid_b) = ([1u8; 32], [2u8; 32]);
        // The pinning side's commit is for session A; forwarded to the pinned node on session B,
        // it does not match there, so the pinned node does not even answer.
        assert!(answer_auth_request(&k, &sid_b, &auth_commit(&sid_a, &pk)).is_none());
        // And a signature the pinned node made on B does not verify on A.
        let sig_b = answer_auth_request(&k, &sid_b, &auth_commit(&sid_b, &pk)).unwrap();
        assert!(!verify_auth_response(&pk, &sid_a, &sig_b));
    }

    #[test]
    fn the_commit_hides_the_key() {
        // Two different pinned keys give unrelated commits; neither reveals the key itself.
        let sid = [9u8; 32];
        let a = auth_commit(&sid, &kp(1).x_only_public_key().0.serialize());
        let b = auth_commit(&sid, &kp(2).x_only_public_key().0.serialize());
        assert_ne!(a, b);
        assert_ne!(&a[..], &kp(1).x_only_public_key().0.serialize()[..]);
    }
}
