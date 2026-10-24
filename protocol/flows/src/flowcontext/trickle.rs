//! Per-peer Poisson inv trickle (spec 06 D-7), replacing the global 500 ms gate that flushed to
//! every peer in one loop on the next call.
//!
//! Each outbound peer has its own exponential timer (mean 0.5 s); inbound peers share one timer
//! per /16 (IPv4) or /32 (IPv6) group (mean 1.0 s), so a spy that opens many inbound connections
//! from one prefix does not get many independent samples of our announce time. A timer task
//! drives the flush. A transaction id is never announced to a peer that announced it to us or to
//! which it was already announced (a per-peer known-inventory LRU of 50,000 ids), and ids within
//! one inv are in random order.

use super::dandelion::prefix_group;
use kaspa_consensus_core::tx::TransactionId;
use kaspa_p2p_lib::PeerKey;
use rand::Rng;
use rand::seq::SliceRandom;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const OUTBOUND_INV_MEAN: Duration = Duration::from_millis(500);
pub const INBOUND_INV_MEAN: Duration = Duration::from_millis(1000);
pub const KNOWN_INVENTORY_CAP: usize = 50_000;
/// How often the timer task wakes up to flush due peers.
pub const TRICKLE_TICK: Duration = Duration::from_millis(25);

fn exp_after<R: Rng>(rng: &mut R, now: Instant, mean: Duration) -> Instant {
    let u: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
    now + mean.mul_f64(-u.ln())
}

#[derive(Default)]
struct KnownInventory {
    set: HashSet<TransactionId>,
    order: VecDeque<TransactionId>,
}

impl KnownInventory {
    fn insert(&mut self, id: TransactionId) {
        if self.set.insert(id) {
            self.order.push_back(id);
            if self.order.len() > KNOWN_INVENTORY_CAP
                && let Some(old) = self.order.pop_front()
            {
                self.set.remove(&old);
            }
        }
    }

    fn contains(&self, id: &TransactionId) -> bool {
        self.set.contains(id)
    }
}

struct PeerTrickle {
    outbound: bool,
    group: [u8; 4],
    queue: Vec<TransactionId>,
    queued: HashSet<TransactionId>,
    next: Instant,
    known: KnownInventory,
}

#[derive(Default)]
pub struct Trickle {
    peers: HashMap<PeerKey, PeerTrickle>,
    group_next: HashMap<[u8; 4], Instant>,
}

impl Trickle {
    /// Adds new peers and forgets gone ones. `peers` = (key, is_outbound, ip).
    pub fn sync_peers<R: Rng>(&mut self, peers: &[(PeerKey, bool, IpAddr)], now: Instant, rng: &mut R) {
        let live: HashSet<PeerKey> = peers.iter().map(|p| p.0).collect();
        self.peers.retain(|k, _| live.contains(k));
        for (key, outbound, ip) in peers {
            self.peers.entry(*key).or_insert_with(|| PeerTrickle {
                outbound: *outbound,
                group: prefix_group(*ip),
                queue: Vec::new(),
                queued: HashSet::new(),
                next: exp_after(rng, now, if *outbound { OUTBOUND_INV_MEAN } else { INBOUND_INV_MEAN }),
                known: KnownInventory::default(),
            });
        }
        let groups: HashSet<[u8; 4]> = self.peers.values().filter(|p| !p.outbound).map(|p| p.group).collect();
        self.group_next.retain(|g, _| groups.contains(g));
        for g in groups {
            self.group_next.entry(g).or_insert_with(|| exp_after(rng, now, INBOUND_INV_MEAN));
        }
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Queues `ids` for every peer (or only `targets`) that does not already know them.
    pub fn enqueue(&mut self, ids: &[TransactionId], targets: Option<&HashSet<PeerKey>>) {
        for (key, p) in self.peers.iter_mut() {
            if targets.is_some_and(|t| !t.contains(key)) {
                continue;
            }
            for id in ids {
                if !p.known.contains(id) && p.queued.insert(*id) {
                    p.queue.push(*id);
                }
            }
        }
    }

    /// `peer` has `ids` (it announced them to us): never announce them to it.
    pub fn note_known(&mut self, peer: &PeerKey, ids: &[TransactionId]) {
        if let Some(p) = self.peers.get_mut(peer) {
            for id in ids {
                p.known.insert(*id);
                if p.queued.remove(id) {
                    p.queue.retain(|x| x != id);
                }
            }
        }
    }

    pub fn knows(&self, peer: &PeerKey, id: &TransactionId) -> bool {
        self.peers.get(peer).is_some_and(|p| p.known.contains(id))
    }

    /// Peers whose timer fired, with their queued ids in random order. Marks the ids known to
    /// the peer and draws the next timer.
    pub fn due<R: Rng>(&mut self, now: Instant, rng: &mut R) -> Vec<(PeerKey, Vec<TransactionId>)> {
        let mut fired_groups = HashSet::new();
        for (g, next) in self.group_next.iter_mut() {
            if *next <= now {
                fired_groups.insert(*g);
                *next = exp_after(rng, now, INBOUND_INV_MEAN);
            }
        }
        let mut out = Vec::new();
        for (key, p) in self.peers.iter_mut() {
            let fire = if p.outbound {
                if p.next <= now {
                    p.next = exp_after(rng, now, OUTBOUND_INV_MEAN);
                    true
                } else {
                    false
                }
            } else {
                fired_groups.contains(&p.group)
            };
            if !fire || p.queue.is_empty() {
                continue;
            }
            let mut ids = std::mem::take(&mut p.queue);
            p.queued.clear();
            ids.shuffle(rng);
            for id in &ids {
                p.known.insert(*id);
            }
            out.push((*key, ids));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_utils::networking::PeerId;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::net::Ipv4Addr;

    fn peer(i: u8, outbound: bool, a: u8) -> (PeerKey, bool, IpAddr) {
        let ip = IpAddr::V4(Ipv4Addr::new(a, i, 0, 1));
        (PeerKey::new(PeerId::from(uuid::Uuid::from_bytes([i; 16])), ip.into()), outbound, ip)
    }

    fn tx(i: u8) -> TransactionId {
        TransactionId::from_bytes([i; 32])
    }

    fn txn(i: u32) -> TransactionId {
        let mut b = [0u8; 32];
        b[..4].copy_from_slice(&i.to_le_bytes());
        b[31] = 1;
        TransactionId::from_bytes(b)
    }

    #[test]
    fn outbound_timers_average_half_a_second() {
        let mut rng = StdRng::seed_from_u64(1);
        let mut t = Trickle::default();
        let start = Instant::now();
        let p = peer(1, true, 10);
        t.sync_peers(&[p], start, &mut rng);
        let mut flushes = 0;
        let mut now = start;
        let end = start + Duration::from_secs(2000);
        let mut k = 0u32;
        while now < end {
            k += 1;
            t.enqueue(&[txn(k)], None);
            if !t.due(now, &mut rng).is_empty() {
                flushes += 1;
            }
            now += Duration::from_millis(5);
        }
        let mean = 2000.0 / flushes as f64;
        assert!((mean - 0.5).abs() < 0.05, "mean interval {mean}");
    }

    #[test]
    fn inbound_peers_in_one_prefix_flush_together() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut t = Trickle::default();
        let now = Instant::now();
        // Three inbound connections from 10.1.x.x share a timer; 10.2 has its own.
        let a = peer(1, false, 10);
        let mut b = peer(1, false, 10);
        b.0 = PeerKey::new(PeerId::from(uuid::Uuid::from_bytes([7; 16])), b.2.into());
        let c = peer(2, false, 10);
        t.sync_peers(&[a, b, c], now, &mut rng);
        let mut together = 0;
        let mut apart = 0;
        let mut clock = now;
        for k in 0..20_000u32 {
            t.enqueue(&[txn(k)], None);
            let fired: HashSet<PeerKey> = t.due(clock, &mut rng).into_iter().map(|x| x.0).collect();
            if fired.contains(&a.0) != fired.contains(&b.0) {
                apart += 1;
            }
            if fired.contains(&a.0) && fired.contains(&b.0) {
                together += 1;
            }
            clock += Duration::from_millis(10);
        }
        assert_eq!(apart, 0);
        assert!(together > 100);
    }

    #[test]
    fn never_announce_back_or_twice() {
        let mut rng = StdRng::seed_from_u64(3);
        let mut t = Trickle::default();
        let now = Instant::now();
        let a = peer(1, true, 10);
        let b = peer(2, true, 10);
        t.sync_peers(&[a, b], now, &mut rng);
        t.note_known(&a.0, &[tx(1)]);
        t.enqueue(&[tx(1), tx(2)], None);
        t.enqueue(&[tx(2)], None);
        let far = now + Duration::from_secs(3600);
        let mut got: HashMap<PeerKey, Vec<TransactionId>> = t.due(far, &mut rng).into_iter().collect();
        assert_eq!(got.remove(&a.0).unwrap(), vec![tx(2)]);
        let mut bs = got.remove(&b.0).unwrap();
        bs.sort();
        assert_eq!(bs, vec![tx(1), tx(2)]);
        t.enqueue(&[tx(1), tx(2)], None);
        assert!(t.due(far + Duration::from_secs(3600), &mut rng).is_empty());
    }

    #[test]
    fn inv_order_is_random() {
        let mut rng = StdRng::seed_from_u64(4);
        let mut t = Trickle::default();
        let now = Instant::now();
        let a = peer(1, true, 10);
        t.sync_peers(&[a], now, &mut rng);
        let ids: Vec<TransactionId> = (0..50).map(tx).collect();
        t.enqueue(&ids, None);
        let got = t.due(now + Duration::from_secs(3600), &mut rng).pop().unwrap().1;
        assert_ne!(got, ids);
        let mut sorted = got.clone();
        sorted.sort();
        let mut want = ids.clone();
        want.sort();
        assert_eq!(sorted, want);
    }

    #[test]
    fn known_inventory_is_bounded() {
        let mut k = KnownInventory::default();
        for i in 0..(KNOWN_INVENTORY_CAP as u32 + 10) {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            k.insert(TransactionId::from_bytes(b));
        }
        assert_eq!(k.set.len(), KNOWN_INVENTORY_CAP);
        assert!(!k.contains(&TransactionId::from_bytes([0; 32])));
    }
}
