use crate::{consensus::test_consensus::TestConsensus, model::services::reachability::ReachabilityService};
use kaspa_consensus_core::{
    BlockHashSet,
    api::ConsensusApi,
    block::{Block, BlockTemplate, MutableBlock, TemplateBuildMode, TemplateTransactionSelector},
    blockhash,
    blockstatus::BlockStatus,
    coinbase::MinerData,
    config::{
        ConfigBuilder,
        params::{ForkActivation, MAINNET_PARAMS, Params},
    },
    constants::{BLOCK_VERSION, TOCCATA_BLOCK_VERSION},
    tx::{ScriptPublicKey, ScriptVec, Transaction},
};
use kaspa_hashes::Hash;
use std::{collections::VecDeque, thread::JoinHandle};

/// Mainnet params with the shielded coinbase disabled. Production mainnet is
/// shielded-by-default (a transparent coinbase there fails the shielded mint), so
/// consensus tests that mine ordinary transparent coinbases to exercise unrelated
/// behavior (ghostdag / pruning / utxo / block templates) opt out explicitly.
fn transparent_mainnet() -> Params {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = false;
    params
}

struct OnetimeTxSelector {
    txs: Option<Vec<Transaction>>,
}

impl OnetimeTxSelector {
    fn new(txs: Vec<Transaction>) -> Self {
        Self { txs: Some(txs) }
    }
}

impl TemplateTransactionSelector for OnetimeTxSelector {
    fn select_transactions(&mut self) -> Vec<Transaction> {
        self.txs.take().unwrap()
    }

    fn reject_selection(&mut self, _tx_id: kaspa_consensus_core::tx::TransactionId) {
        unimplemented!()
    }

    fn is_successful(&self) -> bool {
        true
    }
}

struct TestContext {
    consensus: TestConsensus,
    join_handles: Vec<JoinHandle<()>>,
    miner_data: MinerData,
    simulated_time: u64,
    current_templates: VecDeque<BlockTemplate>,
    current_tips: BlockHashSet,
}

impl Drop for TestContext {
    fn drop(&mut self) {
        self.consensus.shutdown(std::mem::take(&mut self.join_handles));
    }
}

impl TestContext {
    fn new(consensus: TestConsensus) -> Self {
        let join_handles = consensus.init();
        let genesis_hash = consensus.params().genesis.hash;
        let simulated_time = consensus.params().genesis.timestamp;
        Self {
            consensus,
            join_handles,
            miner_data: new_miner_data(),
            simulated_time,
            current_templates: Default::default(),
            current_tips: BlockHashSet::from_iter([genesis_hash]),
        }
    }

    pub fn build_block_template_row(&mut self, nonces: impl Iterator<Item = usize>) -> &mut Self {
        for nonce in nonces {
            self.simulated_time += self.consensus.params().target_time_per_block();
            self.current_templates.push_back(self.build_block_template(nonce as u64, self.simulated_time));
        }
        self
    }

    pub fn assert_row_parents(&mut self) -> &mut Self {
        for t in self.current_templates.iter() {
            assert_eq!(self.current_tips, BlockHashSet::from_iter(t.block.header.direct_parents().iter().copied()));
        }
        self
    }

    pub async fn validate_and_insert_row(&mut self) -> &mut Self {
        self.current_tips.clear();
        while let Some(t) = self.current_templates.pop_front() {
            self.current_tips.insert(t.block.header.hash);
            self.validate_and_insert_block(t.block.to_immutable()).await;
        }
        self
    }

    pub async fn build_and_insert_disqualified_chain(&mut self, mut parents: Vec<Hash>, len: usize) -> Hash {
        // The chain will be disqualified since build_block_with_parents builds utxo-invalid blocks
        for _ in 0..len {
            self.simulated_time += self.consensus.params().target_time_per_block();
            let b = self.build_block_with_parents(parents, 0, self.simulated_time);
            parents = vec![b.header.hash];
            self.validate_and_insert_block(b.to_immutable()).await;
        }
        parents[0]
    }

    pub fn build_block_template(&self, nonce: u64, timestamp: u64) -> BlockTemplate {
        let mut t = self
            .consensus
            .build_block_template(
                self.miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        t.block.header.timestamp = timestamp;
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t
    }

    pub fn build_block_with_parents(&self, parents: Vec<Hash>, nonce: u64, timestamp: u64) -> MutableBlock {
        let mut b = self.consensus.build_block_with_parents_and_transactions(blockhash::NONE, parents, Default::default());
        b.header.timestamp = timestamp;
        b.header.nonce = nonce;
        b.header.finalize(); // This overrides the NONE hash we passed earlier with the actual hash
        b
    }

    pub async fn validate_and_insert_block(&mut self, block: Block) -> &mut Self {
        let status = self.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
        self
    }

    pub fn assert_tips(&mut self) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()), self.current_tips);
        self
    }

    pub fn assert_tips_num(&mut self, expected_num: usize) -> &mut Self {
        assert_eq!(BlockHashSet::from_iter(self.consensus.get_tips().into_iter()).len(), expected_num);
        self
    }

    pub fn assert_virtual_parents_subset(&mut self) -> &mut Self {
        assert!(self.consensus.get_virtual_parents().is_subset(&self.current_tips));
        self
    }

    pub fn assert_valid_utxo_tip(&mut self) -> &mut Self {
        // Assert that at least one body tip was resolved with valid UTXO
        assert!(self.consensus.body_tips().iter().copied().any(|h| self.consensus.block_status(h) == BlockStatus::StatusUTXOValid));
        self
    }

    /// Build a template on the current virtual tips and grind a REAL kHeavyHash
    /// nonce for it (no skip_proof_of_work). At the easiest target this is 1-2
    /// hashes. Returns the mined, finalized block.
    fn mine_real_pow_block(&mut self) -> Block {
        self.mine_real_pow_block_with(Default::default())
    }

    /// As `mine_real_pow_block`, but includes the given transactions (a miner
    /// picking them up from the mempool).
    fn mine_real_pow_block_with(&mut self, txs: Vec<Transaction>) -> Block {
        self.simulated_time += self.consensus.params().target_time_per_block();
        let mut t = self
            .consensus
            .build_block_template(self.miner_data.clone(), Box::new(OnetimeTxSelector::new(txs)), TemplateBuildMode::Standard)
            .unwrap();
        t.block.header.timestamp = self.simulated_time;
        let state = kaspa_pow::State::new(&t.block.header);
        let mut nonce = 0u64;
        while !state.check_pow(nonce).0 {
            nonce += 1;
        }
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t.block.to_immutable()
    }

    /// Build a valid empty template, then INJECT `txs` behind the template validator and recompute
    /// the merkle root — for testing that consensus itself rejects a transaction the template
    /// builder would never have included.
    /// Build a valid template, let `tamper` rewrite its coinbase (a dishonest miner), then recompute
    /// the merkle root and grind real PoW, so only consensus can refuse the result.
    fn mine_real_pow_block_tampering_coinbase(&mut self, tamper: impl FnOnce(&mut Transaction)) -> Block {
        self.simulated_time += self.consensus.params().target_time_per_block();
        let mut t = self
            .consensus
            .build_block_template(self.miner_data.clone(), Box::new(OnetimeTxSelector::new(vec![])), TemplateBuildMode::Standard)
            .unwrap();
        tamper(&mut t.block.transactions[0]);
        t.block.header.hash_merkle_root = kaspa_consensus_core::merkle::calc_hash_merkle_root(t.block.transactions.iter());
        t.block.header.timestamp = self.simulated_time;
        let state = kaspa_pow::State::new(&t.block.header);
        let mut nonce = 0u64;
        while !state.check_pow(nonce).0 {
            nonce += 1;
        }
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t.block.to_immutable()
    }

    fn mine_real_pow_block_injecting(&mut self, txs: Vec<Transaction>) -> Block {
        self.simulated_time += self.consensus.params().target_time_per_block();
        let mut t = self
            .consensus
            .build_block_template(self.miner_data.clone(), Box::new(OnetimeTxSelector::new(vec![])), TemplateBuildMode::Standard)
            .unwrap();
        t.block.transactions.extend(txs);
        t.block.header.hash_merkle_root = kaspa_consensus_core::merkle::calc_hash_merkle_root(t.block.transactions.iter());
        t.block.header.timestamp = self.simulated_time;
        let state = kaspa_pow::State::new(&t.block.header);
        let mut nonce = 0u64;
        while !state.check_pow(nonce).0 {
            nonce += 1;
        }
        t.block.header.nonce = nonce;
        t.block.header.finalize();
        t.block.to_immutable()
    }

    /// As `mine_real_pow_block_with`, but with explicit parents — for building a
    /// competing branch that does not extend the current virtual tips. The block is
    /// only BUILT; the caller inserts it (parents must already be in consensus so the
    /// template builder can resolve their ghostdag/UTXO context).
    fn mine_real_pow_block_on(&mut self, parents: Vec<Hash>, txs: Vec<Transaction>) -> Block {
        self.simulated_time += self.consensus.params().target_time_per_block();
        let mut b = self.consensus.build_utxo_valid_block_with_parents(blockhash::NONE, parents, self.miner_data.clone(), txs);
        b.header.timestamp = self.simulated_time;
        let state = kaspa_pow::State::new(&b.header);
        let mut nonce = 0u64;
        while !state.check_pow(nonce).0 {
            nonce += 1;
        }
        b.header.nonce = nonce;
        b.header.finalize(); // Overrides the NONE hash passed above with the actual hash
        b.to_immutable()
    }
}

/// LIVE real-PoW proof: mine a chain of blocks whose PoW is the actual
/// kHeavyHash — no `skip_proof_of_work` — while paying a shielded (Orchard)
/// coinbase. Every block's header goes through the real `check_pow` path in the
/// pipeline, so reaching UTXOValid means the kHeavyHash PoW verifies on real
/// blocks AND the shielded coinbase mints into the pool. This is the first test
/// that exercises kHeavyHash in consensus for real; all others skip PoW. Uses the
/// easiest target (0x207fffff) so CPU grinding is ~1-2 hashes.
#[tokio::test]
async fn real_kheavyhash_pow_mines_shielded_chain_live() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    // Real PoW (skip_proof_of_work stays false) but trivial difficulty seeded from
    // an easy genesis target, so a nonce is found almost immediately.
    let config = ConfigBuilder::new(params).edit_consensus_params(|p| p.genesis.bits = 0x207fffff).build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("valid orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient)), vec![]);

    let mut tips = BlockHashSet::from_iter([config.genesis.hash]);
    for _ in 0..4 {
        let block = ctx.mine_real_pow_block();
        assert_eq!(tips, BlockHashSet::from_iter(block.header.direct_parents().iter().copied()), "extends the single chain");
        tips = BlockHashSet::from_iter([block.header.hash]);
        let status = ctx.consensus.validate_and_insert_block(block).virtual_state_task.await.unwrap();
        assert!(status.is_utxo_valid_or_pending(), "real-PoW shielded block must be accepted");
    }

    // The chain tip is UTXO-valid: real kHeavyHash verified every header and the
    // shielded coinbase advanced the pool anchor past the empty tree.
    ctx.assert_valid_utxo_tip();
    let empty_anchor = kaspa_shielded_core::Anchor::empty_tree().to_bytes();
    let vp = ctx.consensus.virtual_processor();
    let advanced = ctx
        .consensus
        .body_tips()
        .iter()
        .copied()
        .filter(|h| ctx.consensus.block_status(*h) == BlockStatus::StatusUTXOValid)
        .filter_map(|h| vp.shielded_anchor_at(h).ok())
        .any(|anchor| anchor != empty_anchor);
    assert!(advanced, "shielded coinbase mined under real FishHashPlus must advance the anchor");
}

#[tokio::test]
async fn diag_shielded_coinbase_note_structure() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    let config = ConfigBuilder::new(params).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).unwrap();
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient)), vec![]);

    let empty = kaspa_shielded_core::Anchor::empty_tree().to_bytes();
    let mut parent = config.genesis.hash;
    for i in 0..6u64 {
        ctx.simulated_time += ctx.consensus.params().target_time_per_block();
        let mut t = ctx
            .consensus
            .build_block_template(
                ctx.miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        t.block.header.timestamp = ctx.simulated_time;
        t.block.header.finalize();
        let cb_outs = t.block.transactions[0].outputs.len();
        let cb_out_values: Vec<u64> = t.block.transactions[0].outputs.iter().map(|o| o.value).collect();
        let h = t.block.header.hash;
        ctx.consensus.validate_and_insert_block(t.block.to_immutable()).virtual_state_task.await.unwrap();
        let anchor = ctx.consensus.virtual_processor().shielded_anchor_at(h).ok();
        println!(
            "block {i} hash={h} cb_outputs={cb_outs} values={cb_out_values:?} anchor_advanced={} parent={parent}",
            anchor.map(|a| a != empty).unwrap_or(false)
        );
        parent = h;
    }
}

#[tokio::test]
async fn template_mining_sanity_test() {
    let config = ConfigBuilder::new(transparent_mainnet()).skip_proof_of_work().build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let rounds = 10;
    let width = 3;
    for _ in 0..rounds {
        ctx.build_block_template_row(0..width)
            .assert_row_parents()
            .validate_and_insert_row()
            .await
            .assert_tips()
            .assert_virtual_parents_subset()
            .assert_valid_utxo_tip();
    }
}

/// LIVE proof of the shielded coinbase (PLAN §2.7): with `shielded_coinbase`
/// enabled, mine a row of real blocks whose coinbase pays a shielded (Orchard)
/// address, run them through the real virtual processor, and require the tip to
/// be UTXO-valid. Reaching UTXOValid means every block's coinbase reward was
/// successfully turned into coinbase notes and minted into the shielded pool
/// (a malformed recipient or a turnstile violation would yield InvalidShieldedState
/// and the block would not be UTXO-valid). No transparent coinbase value is created.
#[tokio::test]
async fn shielded_coinbase_mints_into_the_pool_live() {
    // ZKas main params with the shielded coinbase turned on.
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    let config = ConfigBuilder::new(params).skip_proof_of_work().build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    // The miner is paid in the shielded pool: its reward "script_public_key" is a
    // real 43-byte Orchard address (what a ZKas miner reports).
    let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("valid orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient)), vec![]);

    for _ in 0..5 {
        ctx.build_block_template_row(0..3).assert_row_parents().validate_and_insert_row().await.assert_tips().assert_valid_utxo_tip();
    }

    // Directly prove value entered the pool: a UTXO-valid chain tip's shielded
    // anchor must have advanced past the empty tree (coinbase notes were appended).
    let empty_anchor = kaspa_shielded_core::Anchor::empty_tree().to_bytes();
    let vp = ctx.consensus.virtual_processor();
    let advanced = ctx
        .consensus
        .body_tips()
        .iter()
        .copied()
        .filter(|h| ctx.consensus.block_status(*h) == BlockStatus::StatusUTXOValid)
        .filter_map(|h| vp.shielded_anchor_at(h).ok())
        .any(|anchor| anchor != empty_anchor);
    assert!(advanced, "shielded coinbase must have appended notes and advanced the anchor past empty");
}

/// THE end-to-end milestone (PLAN §2): under REAL FishHashPlus PoW, mine a
/// shielded-coinbase chain, then have the "wallet" build a REAL Orchard spend of
/// a mined coinbase note and push it through a mined block. The consensus layer
/// verifies the Halo 2 proof + binding/spend-auth signatures, checks the spend's
/// anchor is finalized, and applies the §2.4 transition (nullifier + turnstile).
/// This is the first fully-live private payment: mining + shielded coinbase +
/// real proof verification + state transition, all through the actual pipeline.
/// Run in release (light cache ~3s; real proof a few seconds).
#[tokio::test]
async fn real_shielded_spend_through_mined_block() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    // Isolate the shielded-spend mechanics from the dev fee: with the dev fee enabled, block 1's
    // coinbase would mint two notes (miner + dev fund) and shift note positions/anchors. This test
    // asserts a single-note coinbase, so disable the dev fee here (it is covered by the coinbase unit test).
    params.dev_fee_recipient = None;
    // Real PoW at trivial difficulty; small finality so the coinbase note's anchor
    // finalizes within a short chain (spends must reference a finalized anchor).
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.finality_depth = 5;
            // Small shielded-spend maturity so the coinbase note's anchor matures
            // within a short chain (a spend must prove a matured, canonical anchor).
            p.blockrate.shielded_anchor_depth = 5;
        })
        .build();
    let net = config.genesis.hash.as_bytes();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    // Block 0 mints no note (genesis merge); block 1's coinbase mints the first and
    // only note, at tree position 0 (verified by diag_shielded_coinbase_note_structure).
    let mut block1 = None;
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
        block1 = Some(b);
    }
    let block1 = block1.unwrap();
    let cb = &block1.transactions[0];
    assert_eq!(cb.outputs.len(), 1, "block 1 coinbase is a single note at position 0");
    let cb_txid = cb.id();
    let note_value = cb.outputs[0].value;
    let anchor1 = ctx.consensus.virtual_processor().shielded_anchor_at(block1.header.hash).unwrap();

    // Mine empty blocks until block 1's anchor matures (its source block, block 1 at
    // blue score 1, must be >= shielded_anchor_depth deep below the spend block).
    // depth = 5, so mining 6 blocks puts the spend block well past maturity.
    for _ in 0..6 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
    }

    // Wallet side: build a REAL proven spend of block 1's coinbase note, paying a
    // recipient (fee = 2_000). The sighash context binds to this exact tx.
    let recipient_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap();
    let output_value = note_value - 2_000;
    let mut spend_tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = spend_tx.shielded_sighash_context();
    let payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend(
        miner_seed,
        cb_txid.as_bytes(),
        0,
        note_value,
        recipient_addr,
        output_value,
        &net,
        &tx_ctx,
    )
    .expect("wallet builds a real spend bundle");
    spend_tx.payload = payload;
    spend_tx.finalize();
    assert!(spend_tx.is_shielded(), "constructed a shielded (v2) transaction");

    // Mine a block that includes the shielded spend and validate it end-to-end.
    let spend_block = ctx.mine_real_pow_block_with(vec![spend_tx.clone()]);
    let spend_block_hash = spend_block.header.hash;
    let status = ctx.consensus.validate_and_insert_block(spend_block).virtual_state_task.await.unwrap();
    assert!(status.is_utxo_valid_or_pending(), "real shielded spend accepted: {status:?}");

    // The spend was actually included and its shielded state applied: the block is
    // UTXO-valid and its anchor advanced beyond block 1's (coinbase + spend outputs).
    assert_eq!(ctx.consensus.block_status(spend_block_hash), BlockStatus::StatusUTXOValid);
    let spend_anchor = ctx.consensus.virtual_processor().shielded_anchor_at(spend_block_hash).unwrap();
    assert_ne!(spend_anchor, anchor1, "spend block's shielded state advanced");
}

/// NEGATIVE / soundness + LIVENESS (PLAN §2.5, task #31): a **cryptographically
/// valid** shielded spend whose anchor has not yet matured must not be applied —
/// but it must be **dropped**, NOT disqualify the block that merges it.
///
/// The spend below is a real, proven Orchard bundle against block 1's *real*
/// anchor — the binding signature, the Halo 2 proof and the spend-auth signature
/// all verify. The ONLY thing wrong is that the anchor is too shallow: it has not
/// reached `shielded_anchor_depth` below the spending block, so `is_shielded_anchor_final`
/// correctly refuses it.
///
/// This is the regression test for the live-mainnet halt: the offending spend is
/// immutably embedded in an already-mined merged block, so hard-rejecting the
/// MERGING block made that block un-mergeable and froze the whole selected chain.
/// The fix drops the spend (exactly as a nullifier double-spend is dropped): the
/// merging child stays UTXO-valid, the sink advances, and — because the spend is
/// filtered out before the state transition — no value is ever created (drop-safety
/// is additionally pinned by the `state`/`shielded` unit tests).
/// The mempool must refuse a shielded spend the state transition would DROP.
///
/// Dropping is deliberate and stays (see `immature_shielded_anchor_spend_is_dropped_not_fatal`
/// — rejecting the merging block froze the chain once). But admission never consulted the
/// anchor index or the nullifier set, so a spend that could never apply was still admitted,
/// relayed and mined. It then acquired a txid and confirmations while moving nothing, and
/// its fee was never charged — making the whole thing free to repeat.
///
/// This is the anchor half: a spend proving against an anchor nowhere near mature.
#[tokio::test]
async fn mempool_refuses_a_spend_whose_anchor_can_never_be_final() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.dev_fee_recipient = None;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.finality_depth = 5;
            // Far deeper than this short chain can reach, so the anchor is certainly immature.
            p.blockrate.shielded_anchor_depth = 1_000;
        })
        .build();
    let net = config.genesis.hash.as_bytes();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    let mut block1 = None;
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
        block1 = Some(b);
    }
    let block1 = block1.unwrap();
    let cb = &block1.transactions[0];
    let note_value = cb.outputs[0].value;

    let recipient_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap();
    let mut spend_tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = spend_tx.shielded_sighash_context();
    spend_tx.payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend(
        miner_seed,
        cb.id().as_bytes(),
        0,
        note_value,
        recipient_addr,
        note_value - 2_000,
        &net,
        &tx_ctx,
    )
    .expect("wallet builds a real spend bundle");
    spend_tx.finalize();

    // The proof is valid and the anchor is real — the only defect is that it is not yet
    // final. Consensus would mine this and silently drop it; admission must not let it in.
    let vp = ctx.consensus.virtual_processor();
    let sink = ctx.consensus.get_sink();
    let verdict = vp.check_mempool_shielded_appliable(&spend_tx, sink, ctx.consensus.get_header(sink).unwrap().blue_score, 0);
    let Err(error) = verdict else {
        panic!("a spend against an immature anchor must be refused at admission, not relayed and mined");
    };
    let text = format!("{error:?}");
    assert!(text.contains("anchor"), "must be refused for the anchor, not something else: {text}");
}

/// The nullifier half: re-offering a spend that has already been applied on chain.
///
/// This is the cheaper griefing shape. A dropped spend pays no fee — nothing leaves the
/// sender — so replaying an already-spent note costs the sender nothing while every node
/// Halo 2-verifies it, once at admission and again on every template build. Refusing it at
/// the door is what makes that cost go away.
#[tokio::test]
async fn mempool_refuses_a_replay_of_an_already_applied_spend() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.dev_fee_recipient = None;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.finality_depth = 5;
            // Shallow, so the coinbase note matures within a short test chain and the spend
            // is genuinely APPLIED rather than dropped.
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build();
    let net = config.genesis.hash.as_bytes();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    let mut block1 = None;
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
        block1 = Some(b);
    }
    let block1 = block1.unwrap();
    let cb = &block1.transactions[0];
    let note_value = cb.outputs[0].value;

    let recipient_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap();
    let mut spend_tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = spend_tx.shielded_sighash_context();
    spend_tx.payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend(
        miner_seed,
        cb.id().as_bytes(),
        0,
        note_value,
        recipient_addr,
        note_value - 2_000,
        &net,
        &tx_ctx,
    )
    .expect("wallet builds a real spend bundle");
    spend_tx.finalize();

    // Let the anchor mature, then mine the spend and a child that merges (and so applies) it.
    for _ in 0..3 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
    }
    let spend_block = ctx.mine_real_pow_block_with(vec![spend_tx.clone()]);
    ctx.consensus.validate_and_insert_block(spend_block).virtual_state_task.await.unwrap();
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
    }

    let vp = ctx.consensus.virtual_processor();
    let sink = ctx.consensus.get_sink();
    // Only meaningful if the spend really was applied — otherwise this would be testing the
    // anchor path again by accident.
    let applied = vp.check_mempool_shielded_appliable(&spend_tx, sink, ctx.consensus.get_header(sink).unwrap().blue_score, 0);
    let Err(error) = applied else {
        panic!("re-offering an already-applied spend must be refused: its nullifier is committed");
    };
    let text = format!("{error:?}");
    assert!(text.contains("nullifier"), "must be refused for the nullifier conflict: {text}");
}

#[tokio::test]
async fn immature_shielded_anchor_spend_is_dropped_not_fatal() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    // Isolate from the dev fee (block 1 would otherwise mint a second coinbase note, shifting the
    // anchor this test pins). Dev fee is covered by the coinbase unit test.
    params.dev_fee_recipient = None;
    // A *large* maturity so a short chain can never mature the anchor: the spend
    // is guaranteed immature no matter the exact blue score.
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.finality_depth = 5;
            p.blockrate.shielded_anchor_depth = 1_000;
        })
        .build();
    let net = config.genesis.hash.as_bytes();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    // Mine block 0 (genesis merge, no note) and block 1 (mints the position-0 note).
    let mut block1 = None;
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
        block1 = Some(b);
    }
    let block1 = block1.unwrap();
    let cb = &block1.transactions[0];
    let cb_txid = cb.id();
    let note_value = cb.outputs[0].value;
    // Sanity: the note's anchor exists and is indexed (so rejection is due to
    // *immaturity*, not an unknown anchor).
    let anchor1 = ctx.consensus.virtual_processor().shielded_anchor_at(block1.header.hash).unwrap();
    let sink_before = ctx.consensus.get_sink();

    // Build a REAL proven spend against block 1's anchor — but do NOT mine the
    // ~1000 blocks needed to mature it.
    let recipient_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap();
    let output_value = note_value - 2_000;
    let mut spend_tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = spend_tx.shielded_sighash_context();
    let payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend(
        miner_seed,
        cb_txid.as_bytes(),
        0,
        note_value,
        recipient_addr,
        output_value,
        &net,
        &tx_ctx,
    )
    .expect("wallet builds a real spend bundle");
    spend_tx.payload = payload;
    spend_tx.finalize();
    // The bundle references block 1's real anchor (so the only defect is maturity).
    let bundle = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes(&spend_tx.payload).unwrap();
    assert_eq!(bundle.anchor, anchor1, "spend proves against block 1's real anchor");

    // Mine block B carrying the immature spend in its body. In Kaspa a block's own
    // transactions are *accepted* by the block that merges it, not by itself, so B's
    // body validity does not yet exercise the anchor-finality gate.
    let spend_block = ctx.mine_real_pow_block_with(vec![spend_tx]);
    let spend_block_hash = spend_block.header.hash;
    assert_eq!(spend_block.transactions.len(), 2, "the immature spend was included in the block body");
    ctx.consensus.validate_and_insert_block(spend_block).virtual_state_task.await.unwrap();

    // Mine child C on top of B. C *merges* B, so B's immature spend now enters C's
    // accepted set and is checked by the shielded state transition. The spend proves
    // against an anchor nowhere near `shielded_anchor_depth` deep, so the maturity
    // gate refuses it — and DROPS it (does not disqualify C). C therefore validates
    // normally (its coinbase mints, the immature spend is simply ignored) and the
    // chain keeps advancing. This is the fix for the observed mainnet halt.
    let child = ctx.mine_real_pow_block();
    let child_hash = child.header.hash;

    // ANTI-INFLATION (the F-01 regression): the dropped spend's fee (2_000) never
    // left the pool, so C's coinbase — which pays B's reward — must re-mint the
    // bare subsidy and NOT the dropped fee. `note_value` is a fee-less block's
    // subsidy at the same emission phase, so it is the exact expected value.
    let child_coinbase_total: u64 = child.transactions[0].outputs.iter().map(|o| o.value).sum();
    assert_eq!(
        child_coinbase_total, note_value,
        "the merging block's coinbase must not re-mint a dropped spend's fee (would be +2_000 unbacked)"
    );

    ctx.consensus.validate_and_insert_block(child).virtual_state_task.await.unwrap();

    // LIVENESS: the block merging an immature-anchor spend is NOT disqualified — it is
    // UTXO-valid and the sink advances to it. (Before the fix this was
    // StatusDisqualifiedFromChain and the chain froze here.)
    assert_eq!(
        ctx.consensus.block_status(child_hash),
        BlockStatus::StatusUTXOValid,
        "merging an immature-anchor spend must NOT disqualify the block (drop the spend, keep liveness)"
    );
    assert_eq!(ctx.consensus.get_sink(), child_hash, "the sink advances to the child — the chain did not halt");
    assert_ne!(ctx.consensus.get_sink(), sink_before, "the chain advanced past the pre-spend sink");

    // ANTI-INFLATION, ledger side: across the block that dropped the spend, the
    // pool grew by exactly the subsidy — cumulative_coinbase minted the coinbase
    // note, cumulative_fees collected nothing (the spend was never applied).
    // Before the fix this delta was subsidy + 2_000: silent unbacked supply.
    let vp = ctx.consensus.virtual_processor();
    let before = vp.shielded_supply_totals_at(spend_block_hash).unwrap();
    let after = vp.shielded_supply_totals_at(child_hash).unwrap();
    let pool_delta =
        (after.cumulative_coinbase - before.cumulative_coinbase) as i128 - (after.cumulative_fees - before.cumulative_fees) as i128;
    assert_eq!(pool_delta, note_value as i128, "the pool must grow by exactly the subsidy when a spend is dropped");
}

/// NEGATIVE / soundness (PLAN §2.5, task #29 — the shallow-anchor value-creation
/// vector): the anchor-finality gate `is_shielded_anchor_final` must reject an
/// anchor whose source block is **not a selected-chain ancestor** of the spending
/// block's selected parent. This is what stops a spend from proving its input note
/// into a tree state that is not in its own past — whether that state lives on an
/// abandoned reorg branch or simply in the chain's *future*. Both reduce to the
/// same `is_chain_ancestor_of(source, selected_parent)` check, so we exercise it on
/// a plain linear chain (no reorg orchestration needed): an anchor from a *later*
/// block is not an ancestor of an *earlier* selected parent.
///
/// Maturity is deliberately made trivial (`shielded_anchor_depth = 1`) and the
/// blue score passed generously, so the ONLY thing under test here is canonicality
/// — the maturity dimension is covered by
/// `immature_shielded_anchor_spend_is_dropped_not_fatal`.
#[tokio::test]
async fn non_canonical_anchor_is_not_final() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff; // trivial real PoW
            p.blockrate.shielded_anchor_depth = 1; // make maturity trivial; isolate canonicality
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    // Mine a linear shielded chain and record each block's hash in chain order.
    let mut chain = Vec::new();
    for _ in 0..6 {
        let b = ctx.mine_real_pow_block();
        let h = b.header.hash;
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
        chain.push(h);
    }

    let vp = ctx.consensus.virtual_processor();
    let empty_anchor = kaspa_shielded_core::Anchor::empty_tree().to_bytes();
    let blue_score = |h: Hash| ctx.consensus.get_header(h).unwrap().blue_score;

    // p (earlier) and q (later, a chain-descendant of p): both have minted notes, so
    // their committed anchors are non-empty and distinct (the tree advanced p→q).
    let (p, q) = (chain[2], chain[4]);
    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(p, q), "p precedes q on the selected chain");
    assert!(!ctx.consensus.reachability_service().is_chain_ancestor_of(q, p), "q does NOT precede p");
    let anchor_p = vp.shielded_anchor_at(p).unwrap();
    let anchor_q = vp.shielded_anchor_at(q).unwrap();
    assert_ne!(anchor_p, empty_anchor, "p minted a note (non-empty anchor)");
    assert_ne!(anchor_q, empty_anchor, "q minted a note (non-empty anchor)");
    assert_ne!(anchor_p, anchor_q, "the note-commitment tree advanced from p to q");

    // POSITIVE: p's anchor is final relative to a spending block whose selected
    // parent is q — p is a canonical ancestor of q and (depth=1) matured.
    assert!(vp.is_shielded_anchor_final(&anchor_p, q, blue_score(q)), "an anchor from a canonical ancestor, matured, must be final");

    // NEGATIVE (canonicality — the #29 defense): q's anchor must NOT be final for a
    // spending block whose selected parent is p. q is not in p's past, so proving a
    // note into q's tree from a p-rooted block would be creating value out of a
    // state that does not exist there. Rejected regardless of (generous) blue score.
    assert!(
        !vp.is_shielded_anchor_final(&anchor_q, p, u64::MAX),
        "an anchor whose source is not an ancestor of the selected parent must be rejected"
    );

    // NEGATIVE (fabricated): an anchor no block ever produced is not a real tree root
    // of any committed block, so it can never be final.
    assert!(!vp.is_shielded_anchor_final(&[0x33u8; 32], q, u64::MAX), "an anchor no block ever produced must be rejected");

    // Genesis's empty-tree anchor is always final (canonical + mature by definition).
    assert!(vp.is_shielded_anchor_final(&empty_anchor, q, blue_score(q)), "the empty-tree (genesis) anchor is always final");
}

/// REORG / F-01 regression (Critical): a shielded spend on an abandoned branch adds
/// its nullifier to the global set; when a heavier competing branch re-spends the
/// SAME note, the reorg down-walk must make the reverted nullifier visible as
/// unspent BEFORE the up-walk validates the rejoining branch. Commit 603afce staged
/// reverts and re-applies in ONE WriteBatch committed after the walk — but RocksDB
/// deletes staged in a batch are invisible to store reads until written
/// (`CachedDbAccess::delete` removes the cache entry, `has()` then falls through to
/// RocksDB where the key is still present), so the rejoining branch's re-spend was
/// wrongly dropped as a double-spend and that outcome was persisted via
/// `commit_utxo_state` — a permanent divergence from nodes that never saw the
/// abandoned branch. The fix commits the down-walk reverts in a first batch before
/// the up-walk.
///
/// Drive: common chain mints note N; branch A spends N (nullifier added); heavier
/// branch B re-spends the SAME N and takes over the selected chain. Assert B's
/// spend outcome equals A's (the same spend applied: fee left the pool exactly
/// once), i.e. B's spend was NOT dropped due to a stale nullifier.
#[tokio::test]
async fn reorg_nullifier_revert_is_visible_to_rejoining_spend() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    // Isolate the shielded-spend mechanics from the dev fee (single-note coinbases,
    // as in the other shielded tests; the dev fee is covered by the coinbase unit test).
    params.dev_fee_recipient = None;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff; // trivial real PoW
            p.blockrate.finality_depth = 5;
            p.blockrate.shielded_anchor_depth = 3; // mature the coinbase note's anchor within a short chain
        })
        .build();
    let net = config.genesis.hash.as_bytes();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    // Common chain: block 1 mints the first (position-0) note N.
    let mut block1 = None;
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
        block1 = Some(b);
    }
    let block1 = block1.unwrap();
    let cb = &block1.transactions[0];
    assert_eq!(cb.outputs.len(), 1, "block 1 coinbase is a single note at position 0");
    let cb_txid = cb.id();
    let note_value = cb.outputs[0].value;
    let anchor1 = ctx.consensus.virtual_processor().shielded_anchor_at(block1.header.hash).unwrap();

    // Extend the common chain until block 1's anchor matures (depth = 3); the last
    // common block is the reorg split point.
    let mut split = block1.header.hash;
    for _ in 0..5 {
        let b = ctx.mine_real_pow_block();
        split = b.header.hash;
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
    }
    let fees_at_split = ctx.consensus.virtual_processor().shielded_supply_totals_at(split).unwrap().cumulative_fees;

    // One REAL proven spend of note N (fee = 2_000), to be carried by BOTH branches.
    let recipient_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap();
    let mut spend_tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = spend_tx.shielded_sighash_context();
    let payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend(
        miner_seed,
        cb_txid.as_bytes(),
        0,
        note_value,
        recipient_addr,
        note_value - 2_000,
        &net,
        &tx_ctx,
    )
    .expect("wallet builds a real spend bundle");
    spend_tx.payload = payload;
    spend_tx.finalize();

    // Build (not yet insert) the competing branch blocks while the selected chain is
    // still the common chain: template-time validation must see note N unspent in the
    // branch PoV. B1 carries the same re-spend of N.
    let b1 = ctx.mine_real_pow_block_on(vec![split], vec![spend_tx.clone()]);
    let b1_hash = b1.header.hash;
    // Branch A: A1 carries the spend on top of the split point; A2 (empty) merges A1
    // and applies the spend — nullifier N enters the global set.
    let a1 = ctx.mine_real_pow_block_on(vec![split], vec![spend_tx.clone()]);
    let a1_hash = a1.header.hash;
    ctx.consensus.validate_and_insert_block(a1).virtual_state_task.await.unwrap();
    let a2 = ctx.mine_real_pow_block_on(vec![a1_hash], vec![]);
    let a2_hash = a2.header.hash;
    let status = ctx.consensus.validate_and_insert_block(a2).virtual_state_task.await.unwrap();
    assert!(status.is_utxo_valid_or_pending(), "branch A applied the spend: {status:?}");
    assert_eq!(ctx.consensus.block_status(a2_hash), BlockStatus::StatusUTXOValid);
    assert_eq!(
        ctx.consensus.virtual_processor().shielded_supply_totals_at(a2_hash).unwrap().cumulative_fees,
        fees_at_split + 2_000,
        "branch A applied the spend: its fee left the pool exactly once"
    );

    // Now feed branch B. B1 alone is shorter than A (no reorg yet); B2 ties; B3 makes
    // B strictly heavier — the virtual selected chain reorgs off A onto B, and B2
    // (which merges B1's re-spend of N) is UTXO-validated during the up-walk.
    ctx.consensus.validate_and_insert_block(b1).virtual_state_task.await.unwrap();
    let b2 = ctx.mine_real_pow_block_on(vec![b1_hash], vec![]);
    let b2_hash = b2.header.hash;
    ctx.consensus.validate_and_insert_block(b2).virtual_state_task.await.unwrap();
    let b3 = ctx.mine_real_pow_block_on(vec![b2_hash], vec![]);
    let b3_hash = b3.header.hash;
    let status = ctx.consensus.validate_and_insert_block(b3).virtual_state_task.await.unwrap();
    assert!(status.is_utxo_valid_or_pending(), "branch B took over the selected chain: {status:?}");
    let vp = ctx.consensus.virtual_processor();

    // The reorg happened: the selected chain now runs through B, not A.
    assert_eq!(ctx.consensus.get_sink(), b3_hash, "the heavier branch B won the selected chain");
    assert_eq!(ctx.consensus.block_status(b3_hash), BlockStatus::StatusUTXOValid);
    assert_eq!(ctx.consensus.block_status(b2_hash), BlockStatus::StatusUTXOValid);
    assert!(!ctx.consensus.reachability_service().is_chain_ancestor_of(a2_hash, b3_hash), "branch A was abandoned by the reorg");

    // F-01 core assertion: B's re-spend of N was NOT dropped as a double-spend against
    // a stale nullifier. B2's accepted set applied the spend — its 2_000 fee left the
    // pool — matching A's outcome for the identical spend. Pre-fix this read
    // `fees_at_split` (spend dropped: reverted nullifier still read SPENT during the
    // up-walk), diverging from nodes that only ever saw branch B.
    assert_eq!(
        vp.shielded_supply_totals_at(b2_hash).unwrap().cumulative_fees,
        fees_at_split + 2_000,
        "B's re-spend must be applied, not dropped against a stale nullifier (F-01)"
    );
    assert_eq!(
        vp.shielded_supply_totals_at(b2_hash).unwrap().cumulative_fees,
        vp.shielded_supply_totals_at(a2_hash).unwrap().cumulative_fees,
        "B's spend outcome equals A's outcome for the identical spend"
    );
}

#[tokio::test]
async fn block_template_version_changes_to_v2_upon_activation() {
    let activation = MAINNET_PARAMS.genesis.daa_score + 10;
    let config = ConfigBuilder::new(transparent_mainnet())
        .skip_proof_of_work()
        .edit_consensus_params(|p| p.toccata_activation = ForkActivation::new(activation))
        .build();
    let consensus = TestConsensus::new(&config);
    let join_handles = consensus.init();
    let miner_data = new_miner_data();

    let mut saw_pre_activation_template = false;
    loop {
        let template = consensus
            .build_block_template(
                miner_data.clone(),
                Box::new(OnetimeTxSelector::new(Default::default())),
                TemplateBuildMode::Standard,
            )
            .unwrap();
        if template.block.header.daa_score >= activation {
            assert!(saw_pre_activation_template);
            assert_eq!(template.block.header.version, TOCCATA_BLOCK_VERSION);
            break;
        }

        saw_pre_activation_template = true;
        assert_eq!(template.block.header.version, BLOCK_VERSION);
        let status = consensus.validate_and_insert_block(template.block.to_immutable()).virtual_state_task.await.unwrap();
        assert!(status.has_block_body());
    }

    consensus.shutdown(join_handles);
}

#[tokio::test]
async fn antichain_merge_test() {
    let config = ConfigBuilder::new(transparent_mainnet())
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Build a large 32-wide antichain
    ctx.build_block_template_row(0..32)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mine a long enough chain s.t. the antichain is fully merged
    for _ in 0..32 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

#[tokio::test]
async fn basic_utxo_disqualified_test() {
    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(transparent_mainnet())
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    // Mine a longer disqualified chain
    let disqualified_tip = ctx.build_and_insert_disqualified_chain(vec![config.genesis.hash], 20).await;

    assert_ne!(sink, disqualified_tip);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(BlockHashSet::from_iter([sink, disqualified_tip]), BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter()));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip));
}

#[tokio::test]
async fn double_search_disqualified_test() {
    // TODO: add non-coinbase transactions and concurrency in order to complicate the test

    kaspa_core::log::try_init_logger("info");
    let config = ConfigBuilder::new(transparent_mainnet())
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.max_block_parents = 4;
            p.mergeset_size_limit = 10;
            p.min_difficulty_window_size = p.difficulty_window_size;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Mine 3 valid blocks over genesis
    ctx.build_block_template_row(0..3)
        .validate_and_insert_row()
        .await
        .assert_tips()
        .assert_virtual_parents_subset()
        .assert_valid_utxo_tip();

    // Mark the one expected to remain on virtual chain
    let original_sink = ctx.consensus.get_sink();

    // Find the roots to be used for the disqualified chains
    let mut virtual_parents = ctx.consensus.get_virtual_parents();
    assert!(virtual_parents.remove(&original_sink));
    let mut iter = virtual_parents.into_iter();
    let root_1 = iter.next().unwrap();
    let root_2 = iter.next().unwrap();
    assert_eq!(iter.next(), None);

    // Mine a valid chain
    for _ in 0..10 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }

    // Get current sink
    let sink = ctx.consensus.get_sink();

    assert!(ctx.consensus.reachability_service().is_chain_ancestor_of(original_sink, sink));

    // Mine a long disqualified chain
    let disqualified_tip_1 = ctx.build_and_insert_disqualified_chain(vec![root_1], 30).await;

    // And another shorter disqualified chain
    let disqualified_tip_2 = ctx.build_and_insert_disqualified_chain(vec![root_2], 20).await;

    assert_eq!(ctx.consensus.get_block_status(root_1), Some(BlockStatus::StatusUTXOValid));
    assert_eq!(ctx.consensus.get_block_status(root_2), Some(BlockStatus::StatusUTXOValid));

    assert_ne!(sink, disqualified_tip_1);
    assert_ne!(sink, disqualified_tip_2);
    assert_eq!(sink, ctx.consensus.get_sink());
    assert_eq!(
        BlockHashSet::from_iter([sink, disqualified_tip_1, disqualified_tip_2]),
        BlockHashSet::from_iter(ctx.consensus.get_tips().into_iter())
    );
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_1));
    assert!(!ctx.consensus.get_virtual_parents().contains(&disqualified_tip_2));

    // Mine a long enough valid chain s.t. both disqualified chains are fully merged
    for _ in 0..30 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
    }
    ctx.assert_tips_num(1);
}

fn new_miner_data() -> MinerData {
    let secp = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (_sk, pk) = secp.generate_keypair(&mut rng);
    let script = ScriptVec::from_slice(&pk.serialize());
    MinerData::new(ScriptPublicKey::new(0, script), vec![])
}

fn inactivity_shortcut_config() -> kaspa_consensus_core::config::Config {
    ConfigBuilder::new(transparent_mainnet())
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.finality_depth = 2;
            p.toccata_activation = ForkActivation::always();
        })
        .build()
}

/// Blocks with `bs <= finality_depth` have no resolvable shortcut yet;
/// the recorded `inactivity_shortcut_block` clamps to genesis, which folds
/// to `ZERO_HASH` via `inactivity_shortcut()` and seeds forward walks
/// correctly once descendants cross `bs = finality_depth + 1`.
#[tokio::test]
async fn inactivity_shortcut_block_clamps_to_genesis_within_finality_depth() {
    let config = inactivity_shortcut_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let finality_depth = config.finality_depth();
    assert_eq!(finality_depth, 2);

    let mut chain = vec![config.genesis.hash];
    for _ in 0..2 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
        chain.push(ctx.consensus.get_sink());
    }

    for hash in chain.iter().copied().skip(1) {
        let header = ctx.consensus.get_header(hash).unwrap();
        assert!(header.blue_score <= finality_depth);
        let meta = ctx.consensus.smt_block_metadata(hash);
        assert_eq!(meta.inactivity_shortcut_block(), config.genesis.hash, "bs={}", header.blue_score);
    }
}

/// Tip at `bs = finality_depth + 4` records the chain block at
/// `bs = target_bs = tip_bs - finality_depth - 1` as its
/// inactivity_shortcut block hash.
#[tokio::test]
async fn inactivity_shortcut_resolves_to_chain_block_at_target_bs() {
    let config = inactivity_shortcut_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let finality_depth = config.finality_depth();

    let mut chain = Vec::new();
    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
        chain.push(ctx.consensus.get_sink());
    }

    let tip = *chain.last().unwrap();
    let tip_header = ctx.consensus.get_header(tip).unwrap();
    assert_eq!(tip_header.blue_score, 6);
    let target_bs = tip_header.blue_score - finality_depth - 1; // = 3

    let expected_block = *chain.iter().find(|h| ctx.consensus.get_header(**h).unwrap().blue_score == target_bs).unwrap();
    let recorded = ctx.consensus.smt_block_metadata(tip).inactivity_shortcut_block();
    assert_eq!(recorded, expected_block);
}

/// Consecutive chain blocks: the inactivity_shortcut advances by one chain
/// block per parent-to-child step, since `target_bs` grows in lockstep with
/// `blue_score` on a no-merge chain.
#[tokio::test]
async fn inactivity_shortcut_advances_one_block_per_chain_step() {
    let config = inactivity_shortcut_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    let mut chain = vec![config.genesis.hash];
    for _ in 0..6 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
        chain.push(ctx.consensus.get_sink());
    }

    for (i, hash) in chain.iter().copied().enumerate().skip(4) {
        let expected = chain[i - 3];
        assert_eq!(ctx.consensus.smt_block_metadata(hash).inactivity_shortcut_block(), expected, "block index {i}");
    }
}

/// Canonical-`R`, host side, against a *real* mined DAG block.
///
/// This is the Tier-1 gap `zkbridge.md` §3 tracked: nothing assembled a real seq_commit witness
/// from live chain data. Here the production `get_seq_commit_lane_proof` RPC builder emits the
/// witness fields for a merging chain block `B` (context hash, active-lanes root, the ordered
/// mergeset `miner_payload_leaves`), and the shielded-core host assembler
/// [`SeqCommitWitness::assemble`] — the exact routine the peg-out relayer feeds the guest —
/// reconstructs `B`'s on-chain `seq_commit` from them plus one `get_block(K)` for the merge-mined
/// block `K`. Proving the reconstruction is byte-identical to the value the covenant reads via
/// `OpChainblockSeqCommit` is what turns canonical-`R` from "green in dev mode" into "works on real
/// blocks".
#[tokio::test]
async fn canonical_r_witness_reconstructs_seq_commit_from_mined_block() {
    use kaspa_seq_commit::hashing::miner_payload_leaf;
    use kaspa_seq_commit::types::MinerPayloadLeafInput;
    use kaspa_shielded_core::witness_chain::SeqCommitWitness;

    let config = inactivity_shortcut_config(); // toccata=always, finality_depth=2
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // Warm the chain a few linear blocks so we're comfortably past genesis/pruning point.
    for _ in 0..3 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }

    // Two sibling blocks off the same tips (both templates are built before either is inserted, so
    // they share parents and both carry valid coinbases), then a block `B` that merges them.
    ctx.build_block_template_row(0..2).validate_and_insert_row().await;
    let siblings: Vec<Hash> = ctx.current_tips.iter().copied().collect();
    assert_eq!(siblings.len(), 2, "expected two sibling tips to merge");
    ctx.build_block_template_row(0..1).validate_and_insert_row().await;

    // `B` is the merging chain block (the new sink). One of the two siblings is its selected parent
    // (excluded from the mergeset leaves); the other, `K`, is the sole mergeset-without-SP member,
    // so exactly its leaf appears in the node-emitted `miner_payload_leaves`.
    let b = ctx.consensus.get_sink();
    let b_header = ctx.consensus.get_header(b).unwrap();
    let proof = ctx.consensus.get_seq_commit_lane_proof(b, Hash::from_bytes([0u8; 32])).expect("lane proof for chain block B");
    assert!(!proof.miner_payload_leaves.is_empty(), "B must merge at least one non-selected-parent block");

    // Identify `K` as a sibling whose miner-payload leaf the node placed in B's mergeset (works
    // whichever sibling ended up as the selected parent).
    let k = siblings
        .iter()
        .copied()
        .find(|s| {
            let h = ctx.consensus.get_header(*s).unwrap();
            let payload = ctx.consensus.get_block(*s).unwrap().transactions[0].payload.clone();
            let leaf = miner_payload_leaf(MinerPayloadLeafInput {
                block_hash: s,
                blue_work_be_bytes: &h.blue_work.to_be_bytes(),
                payload: &payload,
            });
            proof.miner_payload_leaves.contains(&leaf)
        })
        .expect("one sibling must be the merged (non-selected-parent) block K");

    let k_header = ctx.consensus.get_header(k).unwrap();
    let k_coinbase_payload = ctx.consensus.get_block(k).unwrap().transactions[0].payload.clone();

    // Assemble the witness exactly as the peg-out relayer would: node-provided mergeset ordering +
    // one get_block(K), no client-side mergeset reasoning.
    let witness = SeqCommitWitness::assemble(
        k,
        k_header.blue_work.to_be_bytes().to_vec(),
        k_coinbase_payload,
        &proof.miner_payload_leaves,
        proof.context_hash,
        proof.lanes_root,
        proof.inactivity_shortcut,
        proof.parent_seq_commit,
    )
    .expect("K must be a member of B's mergeset");

    // Post-Toccata, the header's accepted_id_merkle_root IS the block's seq_commit — the value the
    // covenant reads on-chain. The host reconstruction must match it byte-for-byte.
    assert_eq!(
        witness.recompute_seq_commit().unwrap(),
        b_header.accepted_id_merkle_root,
        "host-assembled witness must reproduce B's on-chain seq_commit"
    );

    // Tightness: perturbing any carried field must break the reconstruction.
    let mut bad = witness.clone();
    bad.context_hash = Hash::from_bytes([0xab; 32]);
    assert_ne!(bad.recompute_seq_commit().unwrap(), b_header.accepted_id_merkle_root, "context_hash must be load-bearing");
    let mut bad = witness.clone();
    bad.parent_seq_commit = Hash::from_bytes([0xcd; 32]);
    assert_ne!(bad.recompute_seq_commit().unwrap(), b_header.accepted_id_merkle_root, "parent_seq_commit must be load-bearing");

    // A block that is not in B's mergeset must be rejected by the assembler.
    let outsider = SeqCommitWitness::assemble(
        b, // B itself is never in its own mergeset
        b_header.blue_work.to_be_bytes().to_vec(),
        ctx.consensus.get_block(b).unwrap().transactions[0].payload.clone(),
        &proof.miner_payload_leaves,
        proof.context_hash,
        proof.lanes_root,
        proof.inactivity_shortcut,
        proof.parent_seq_commit,
    );
    assert_eq!(outsider.err(), Some(kaspa_shielded_core::witness_chain::WitnessError::TargetNotInMergeset));
}

/// AGE WINDOW (audit F-04/F-05, task test #1/#2 — predicate level): an anchor is
/// final iff its source block's blue-score age lies in `[shielded_anchor_depth,
/// max_shielded_anchor_age]` — both bounds inclusive. Below the depth the anchor is
/// immature (PLAN §2.5); above the max age it is uniformly rejected on every node
/// class (fail-closed), which is what kills the abandoned-anchor inflation vector
/// and the full-vs-IBD-seeded divergence. Exercises the gate directly on a real
/// mined chain (no proving cost).
#[tokio::test]
async fn shielded_anchor_age_window_bounds() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.dev_fee_recipient = None; // single-note coinbases (determinism)
    let config = ConfigBuilder::new(params)
        .skip_proof_of_work()
        .edit_consensus_params(|p| {
            p.blockrate.shielded_anchor_depth = 2;
            p.blockrate.max_shielded_anchor_age = 5;
        })
        .build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    // Linear chain: the i-th mined block has blue score i+1.
    let mut chain = Vec::new();
    for _ in 0..9 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await.assert_valid_utxo_tip();
        chain.push(ctx.consensus.get_sink());
    }

    let vp = ctx.consensus.virtual_processor();
    let blue_score = |h: Hash| ctx.consensus.get_header(h).unwrap().blue_score;
    let source = chain[2]; // blue score 3
    assert_eq!(blue_score(source), 3);
    let anchor = vp.shielded_anchor_at(source).unwrap();
    assert_ne!(anchor, kaspa_shielded_core::Anchor::empty_tree().to_bytes(), "the chain minted notes by blue score 3");
    assert_eq!(vp.shielded_state_manager.anchor_source_block(&anchor).unwrap(), Some(source), "anchor indexed to its source");

    let final_at = |q: Hash| vp.is_shielded_anchor_final(&anchor, q, blue_score(q));
    // q's blue score minus the source's (3) is the anchor age:
    assert!(!final_at(chain[3]), "age 1 < depth 2: immature anchor must be rejected");
    assert!(final_at(chain[4]), "age 2 == shielded_anchor_depth: in-window (lower bound inclusive) must be final");
    assert!(final_at(chain[7]), "age 5 == max_shielded_anchor_age: in-window (upper bound inclusive) must be final");
    assert!(!final_at(chain[8]), "age 6 > max_shielded_anchor_age 5: over-aged anchor must be rejected (F-04/F-05)");
}

/// NEGATIVE / soundness + LIVENESS, upper age bound (audit F-04/F-05, task test
/// #2): a **cryptographically valid** shielded spend proving against an anchor
/// older than `max_shielded_anchor_age` must be DROPPED (spend not applied, fee
/// not re-minted) — exactly like an immature-anchor spend — without
/// disqualifying the merging block. Before the age window, an over-aged anchor
/// on the canonical chain resolved as final indefinitely (and once its source
/// pruned, the fail-open short-circuit kept it final forever — F-04).
///
/// Mirrors `immature_shielded_anchor_spend_is_dropped_not_fatal`, but the only
/// defect here is that the anchor is TOO OLD: maturity (depth = 2) is satisfied
/// (age 11 ≥ 2 at merge time), so rejection can only come from the upper bound
/// (age 11 > max age 5). A positive predicate control confirms the same anchor
/// IS final while inside the window.
#[tokio::test]
async fn overaged_shielded_anchor_spend_is_dropped() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.dev_fee_recipient = None; // single-note coinbases (fee accounting below)
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff; // trivial real PoW
            p.blockrate.finality_depth = 5;
            p.blockrate.shielded_anchor_depth = 2; // maturity easily satisfied...
            p.blockrate.max_shielded_anchor_age = 5; // ...but the upper bound is not
        })
        .build();
    let net = config.genesis.hash.as_bytes();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    // chain[0]'s mergeset is only genesis (never rewarded), so it mints no note;
    // chain[1] mints the first and only note, at tree position 0. anchor1 is the
    // tree root chain[1] produced.
    let mut chain = Vec::new();
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        chain.push(b.header.hash);
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
    }
    let block1 = ctx.consensus.get_block(chain[1]).unwrap();
    let cb = &block1.transactions[0];
    assert_eq!(cb.outputs.len(), 1, "block chain[1] coinbase is a single note at position 0");
    let cb_txid = cb.id();
    let note_value = cb.outputs[0].value;
    let anchor1 = ctx.consensus.virtual_processor().shielded_anchor_at(chain[1]).unwrap();

    // Mine 8 empty blocks: tip is now blue score 10, anchor1's source (chain[1],
    // blue score 2) is 8 deep — matured (>= 2) but already older than the max age (5).
    for _ in 0..8 {
        let b = ctx.mine_real_pow_block();
        chain.push(b.header.hash);
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
    }

    // Predicate sanity: the SAME anchor is final inside the window (age 2 at
    // chain[3], blue score 4) but over-aged at the tip (age 8 > 5).
    {
        let vp = ctx.consensus.virtual_processor();
        let blue_score = |h: Hash| ctx.consensus.get_header(h).unwrap().blue_score;
        assert!(vp.is_shielded_anchor_final(&anchor1, chain[3], blue_score(chain[3])), "positive control: age 2 is in [2, 5]");
        let tip = ctx.consensus.get_sink();
        assert!(!vp.is_shielded_anchor_final(&anchor1, tip, blue_score(tip)), "age 8 > max age 5: over-aged (F-04/F-05)");
    }

    // Wallet side: build a REAL proven spend of block 1's coinbase note against
    // anchor1 (the bundle is cryptographically valid — the anchor is just too old).
    let recipient_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap();
    let mut spend_tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = spend_tx.shielded_sighash_context();
    let payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend(
        miner_seed,
        cb_txid.as_bytes(),
        0,
        note_value,
        recipient_addr,
        note_value - 2_000,
        &net,
        &tx_ctx,
    )
    .expect("wallet builds a real spend bundle");
    spend_tx.payload = payload;
    spend_tx.finalize();
    let bundle = kaspa_shielded_core::bundle::ShieldedBundle::from_bytes(&spend_tx.payload).unwrap();
    assert_eq!(bundle.anchor, anchor1, "spend proves against block 1's real (over-aged) anchor");

    // Mine block B carrying the spend, then child C merging B. C's shielded state
    // transition checks the spend's anchor: age 9 > max age 5 ⇒ DROPPED (not fatal).
    let spend_block = ctx.mine_real_pow_block_with(vec![spend_tx]);
    let spend_block_hash = spend_block.header.hash;
    assert_eq!(spend_block.transactions.len(), 2, "the over-aged spend was included in the block body");
    ctx.consensus.validate_and_insert_block(spend_block).virtual_state_task.await.unwrap();

    let child = ctx.mine_real_pow_block();
    let child_hash = child.header.hash;

    // ANTI-INFLATION: the dropped spend's fee (2_000) never left the pool, so C's
    // coinbase re-mints only the bare subsidy (note_value), not subsidy + fee.
    let child_coinbase_total: u64 = child.transactions[0].outputs.iter().map(|o| o.value).sum();
    assert_eq!(child_coinbase_total, note_value, "the merging block's coinbase must not re-mint a dropped spend's fee");

    ctx.consensus.validate_and_insert_block(child).virtual_state_task.await.unwrap();

    // LIVENESS: merging an over-aged-anchor spend does NOT disqualify the block.
    assert_eq!(ctx.consensus.block_status(child_hash), BlockStatus::StatusUTXOValid, "drop the spend, keep liveness");
    assert_eq!(ctx.consensus.get_sink(), child_hash, "the sink advances to the child — the chain did not halt");

    // ANTI-INFLATION, ledger side: across the block that dropped the spend, the
    // pool grew by exactly the subsidy.
    let vp = ctx.consensus.virtual_processor();
    let before = vp.shielded_supply_totals_at(spend_block_hash).unwrap();
    let after = vp.shielded_supply_totals_at(child_hash).unwrap();
    let pool_delta =
        (after.cumulative_coinbase - before.cumulative_coinbase) as i128 - (after.cumulative_fees - before.cumulative_fees) as i128;
    assert_eq!(pool_delta, note_value as i128, "the pool must grow by exactly the subsidy when a spend is dropped");
}

/// A **pruned** node must still be able to enumerate the whole selected chain for a wallet scan.
///
/// On an all-shielded chain a wallet cannot rebuild from the UTXO set — it replays the per-chain-block
/// shielded scan archive, which the pruner retains forever. But the enumeration it needed
/// (`get_virtual_chain_from_block` → `calculate_chain_path`) walks reachability, which pruning deletes
/// below the retention root. The result was a node physically holding every note commitment back to
/// genesis while refusing to serve them, so a restore-from-seed reported a partial balance.
///
/// `get_shielded_chain_range` reads the retained `index -> hash` chain index instead. This test pins the
/// three properties the wallet path depends on: it walks from genesis, it agrees block-for-block with the
/// reachability path it replaces, and it reports "re-anchor" (rather than a bogus range) for a hash that
/// is not on the selected chain.
#[tokio::test]
async fn shielded_chain_range_enumerates_from_genesis_without_reachability() {
    let config = inactivity_shortcut_config(); // toccata=always
    let mut ctx = TestContext::new(TestConsensus::new(&config));

    // A short linear chain plus a merge, so the range covers a non-trivial (wide) shape too.
    for _ in 0..4 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }
    ctx.build_block_template_row(0..2).validate_and_insert_row().await;
    ctx.build_block_template_row(0..1).validate_and_insert_row().await;

    let genesis = config.genesis.hash;
    let sink = ctx.consensus.get_sink();

    // 1. It enumerates from genesis, in chain order, ending at the sink.
    let range = ctx.consensus.get_shielded_chain_range(genesis, 1000).unwrap().expect("genesis is on the selected chain");
    assert!(!range.is_empty(), "a chain with blocks must yield a non-empty range from genesis");
    assert!(!range.contains(&genesis), "the range is strictly *after* low");
    assert_eq!(*range.last().unwrap(), sink, "the range must reach the current sink");

    // 2. It agrees exactly with the reachability path it replaces — same blocks, same order.
    //    This is the substitution the RPC makes, so a divergence here is a wallet-visible divergence.
    let via_reachability = ctx.consensus.get_virtual_chain_from_block(genesis, Some(1000)).unwrap().added;
    assert_eq!(range, via_reachability, "index enumeration must match the reachability chain path block-for-block");

    // 3. `limit` is honoured, and resuming from the last returned block continues without a gap or overlap
    //    — the exact paging loop a wallet runs.
    let page = ctx.consensus.get_shielded_chain_range(genesis, 2).unwrap().unwrap();
    assert_eq!(page.len(), 2, "limit must bound the page");
    assert_eq!(page[..], range[..2], "the first page is the head of the full range");
    let next = ctx.consensus.get_shielded_chain_range(page[1], 1000).unwrap().unwrap();
    assert_eq!(next, range[2..], "resuming from the page's last block continues exactly where it left off");

    // 4. A hash that is not a selected-chain block yields `None` (= re-anchor), never a wrong range.
    //    `apply_changes` deletes the index entry of any block it removes from the chain, so this is
    //    also how a reorged-out anchor is detected.
    assert!(
        ctx.consensus.get_shielded_chain_range(Hash::from_bytes([0xab; 32]), 10).unwrap().is_none(),
        "an unknown/off-chain anchor must report re-anchor rather than an arbitrary range"
    );

    // 5. Every block the range yields is servable, i.e. the enumerator never hands the wallet a
    //    hash the scan stream then chokes on.
    for hash in &range {
        let data = ctx.consensus.get_shielded_chain_block_data(*hash).expect("scan data for a chain block");
        assert_eq!(data.hash, *hash);
    }
}

/// The pruned-node guarantee, on the network shape that actually ships: `shielded_coinbase`.
///
/// The companion test above runs on `transparent_mainnet()`, where a chain block with no shielded
/// activity records nothing in the scan archive — `persist` only writes when there are coinbase
/// outputs or accepted actions — so serving it after pruning would still need the (pruned) header
/// and ghostdag stores. On a shielded-coinbase network that hole cannot occur: every chain block
/// mints its reward as coinbase notes, so every chain block has a scan record, and
/// `shielded_chain_block_data` answers it entirely from the retained archive. That is what makes
/// "a pruned node can still rebuild a wallet from genesis" true for ZKas mainnet specifically.
#[tokio::test]
async fn shielded_chain_range_is_fully_servable_from_the_retained_archive() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.toccata_activation = ForkActivation::always();
    let config = ConfigBuilder::new(params).skip_proof_of_work().build();

    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let recipient = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).expect("valid orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&recipient)), vec![]);

    for _ in 0..5 {
        ctx.build_block_template_row(0..1).validate_and_insert_row().await;
    }

    let range = ctx.consensus.get_shielded_chain_range(config.genesis.hash, 1000).unwrap().expect("genesis is on chain");
    assert_eq!(*range.last().unwrap(), ctx.consensus.get_sink());

    // The property the wallet depends on: once a block actually mints, the scan archive alone
    // carries the mint, so the note stream survives losing bodies, headers and reachability.
    //
    // Genesis' own child is the documented exception and the reason this loop skips the head of
    // the range: its only mergeset member is genesis, which is outside the DAA window, so
    // `expected_coinbase_transaction` emits no outputs, `persist` writes no scan record, and
    // `shielded_chain_block_data` answers from the (prunable) header/ghostdag stores instead.
    // That block mints nothing, so no wallet can hold a note from it and nothing is lost — but
    // it is the one block of the chain that is NOT servable from the retained archive alone.
    // EVERY block must resolve out of the scan archive, not out of the header/ghostdag fallback —
    // that fallback reads stores pruning deletes, so a block relying on it becomes a hole in the
    // wallet's scan stream the moment the node prunes. A real archive record always carries the
    // block's own coinbase txid; the fallback yields the zero-hash sentinel, so that is the
    // discriminator. Genesis' child mints nothing (its only mergeset member is genesis, outside
    // the DAA window) and is exactly the block that used to be skipped by `persist`.
    let mut minting = 0usize;
    for hash in &range {
        let data = ctx.consensus.get_shielded_chain_block_data(*hash).expect("scan data for a chain block");
        assert_eq!(data.hash, *hash);
        assert_ne!(
            data.coinbase_txid,
            kaspa_hashes::Hash::default(),
            "every chain block must be served from the retained archive, not the prunable fallback"
        );
        if !data.coinbase_outputs.is_empty() {
            minting += 1;
        }
    }
    assert!(minting >= 3, "expected several minting blocks in the range, got {minting}");
}

/// AUDIT 2026-10-05 B-1 / F-1 (ZK-01), ported from the lead auditor's proof of concept and
/// extended. The import must refuse peer anchor pairs whose source is not a provable window
/// block (future block, block that never existed), must not take the peer's blue score, and
/// must still accept an honest in-window pair, or a fresh node wedges on its first spend.
#[tokio::test]
async fn imported_anchor_pairs_are_kept_only_for_provable_window_sources() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    let mut chain = Vec::new();
    for _ in 0..8 {
        let b = ctx.mine_real_pow_block();
        let h = b.header.hash;
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
        chain.push(h);
    }
    let vp = ctx.consensus.virtual_processor();
    let blue_score = |h: Hash| ctx.consensus.get_header(h).unwrap().blue_score;
    let (honest_src, pp, real_future_block, tip) = (chain[1], chain[2], chain[5], chain[7]);
    let r_honest = [0x22u8; 32];
    let r_future = [0x33u8; 32];
    let r_ghost = [0x44u8; 32];
    let s_ghost = Hash::from_bytes([0x55u8; 32]);

    let mut md = vp.shielded_state_manager_ref().export_pruning_point_shielded(pp).unwrap().expect("pp has shielded state");
    md.in_window_anchors.push((r_honest, honest_src));
    md.in_window_anchors.push((r_future, real_future_block));
    md.in_window_anchors.push((r_ghost, s_ghost));
    md.in_window_anchor_source_scores.push((s_ghost, blue_score(tip).saturating_sub(10)));
    // A lying score for a real source must be replaced by the header's own value.
    md.in_window_anchor_source_scores.push((honest_src, 0));
    let committed = md.state_root;
    let wire = kaspa_consensus_core::api::ShieldedExportMetadata { data: md.to_wire_bytes(), nullifier_count: 0 };
    let mut none = std::iter::empty::<Vec<[u8; 32]>>();
    ctx.consensus.import_pruning_point_shielded(pp, wire, Some(committed), &mut none).expect("honest state imports");

    assert!(
        !vp.is_shielded_anchor_final(&r_future, tip, blue_score(tip)),
        "a pair naming a block above the pruning point must not be seeded"
    );
    assert!(!vp.is_shielded_anchor_final(&r_ghost, tip, blue_score(tip)), "a pair naming a block with no header must not be seeded");
    assert_eq!(
        vp.shielded_state_manager_ref().attested_source_blue_score(honest_src).unwrap(),
        Some(blue_score(honest_src)),
        "the stored score is the header's, not the peer's"
    );
    assert_eq!(vp.shielded_state_manager_ref().attested_source_blue_score(s_ghost).unwrap(), None, "no score for a dropped source");
    assert!(
        vp.shielded_state_manager_ref().anchor_producer_blocks(&r_honest).unwrap().contains(&honest_src),
        "an honest in-window pair is still seeded"
    );

    // Valid metadata, stream longer than declared: refused as soon as it overruns, and the
    // previously imported state is left exactly as it was (nothing is cleared on failure).
    let md = vp.shielded_state_manager_ref().export_pruning_point_shielded(pp).unwrap().expect("pp has shielded state");
    let wire = kaspa_consensus_core::api::ShieldedExportMetadata { data: md.to_wire_bytes(), nullifier_count: 0 };
    let mut over = vec![vec![[7u8; 32]; 2]].into_iter();
    let err = ctx.consensus.import_pruning_point_shielded(pp, wire, Some(committed), &mut over).unwrap_err();
    assert!(err.to_string().contains("exceed the declared count"), "early-overrun error, got: {err}");
    assert!(
        vp.shielded_state_manager_ref().anchor_producer_blocks(&r_honest).unwrap().contains(&honest_src),
        "a failed import must not clear the state imported before it"
    );
}

fn fork_config() -> kaspa_consensus_core::config::Config {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.security_fork_activation = ForkActivation::always();
    ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build()
}

/// Security fork, self-consistency: with the fork active every block's coinbase commits
/// `zkas_state_root1` of its selected parent, so the template and validation must compute the
/// same versioned root and the same anchor window, block after block. Then the pruning-point
/// export must re-bind to that committed root, and a tampered window entry or dev accrual must not.
#[tokio::test]
async fn security_fork_chain_commits_v1_roots_and_the_window_rebinds() {
    let config = fork_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);
    let mut chain = Vec::new();
    for _ in 0..12 {
        let b = ctx.mine_real_pow_block();
        let h = b.header.hash;
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("every post-fork block validates");
        chain.push(h);
    }
    let vp = ctx.consensus.virtual_processor();
    let mgr = vp.shielded_state_manager_ref();
    for h in &chain {
        assert!(mgr.window_at(*h).unwrap().is_some(), "every post-fork chain block has a window");
        assert!(mgr.window_entry(*h).unwrap().is_some(), "and an entry");
    }
    let pp = chain[8];
    let committed = vp.shielded_state_root_at(pp).unwrap();
    assert_ne!(committed, mgr.state_root_at(pp).unwrap(), "post-fork root is the v1 root, not v0");

    let wire = vp.export_pruning_point_shielded(pp).unwrap().expect("pp exports");
    let md = crate::processes::shielded::PruningPointShieldedMetadata::from_wire_bytes(&wire.data).unwrap();
    assert!(!md.window_entries.is_empty(), "a post-fork pruning point exports its window entries");
    vp.verify_import_binding_versioned(pp, &md, committed).expect("honest export re-binds to the committed root");

    let mut tampered = md.clone();
    tampered.window_entries[0].root = [0xEE; 32];
    assert!(vp.verify_import_binding_versioned(pp, &tampered, committed).is_err(), "a substituted anchor root is refused");
    let mut tampered = md.clone();
    tampered.window_entries.remove(0);
    assert!(vp.verify_import_binding_versioned(pp, &tampered, committed).is_err(), "an omitted window entry is refused");
    let mut tampered = md.clone();
    tampered.dev_accrued = tampered.dev_accrued.wrapping_add(1);
    assert!(vp.verify_import_binding_versioned(pp, &tampered, committed).is_err(), "a different dev accrual is refused");
}

/// Round-2 audit, pre-fork k + 2 stall. Two 18-block chains and one extra block, all forked from
/// the same block: from one chain's tip, the other chain's 18 blocks are all blue (each has exactly
/// k = 18 blues in its anticone) and the extra block is red. The coinbase every node must build for
/// that virtual has 19 blue rewards, the red reward and the dev note: k + 3 = 21 outputs, over the
/// pre-fork cap of k + 2, so every template was invalid and the chain could not advance. The
/// virtual now merges fewer tips, so the next template is valid, and the tips left out are merged
/// by the blocks after it.
#[tokio::test]
async fn pre_fork_virtual_never_builds_an_unmineable_coinbase() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    assert!(params.dev_fee_recipient.is_some() && !params.security_fork_activation.is_active(1_000));
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);
    let base = ctx.mine_real_pow_block();
    let base_hash = base.header.hash;
    ctx.consensus.validate_and_insert_block(base).virtual_state_task.await.unwrap();
    let k = config.params.ghostdag_k() as usize;
    for _ in 0..2 {
        let mut tip = base_hash;
        for _ in 0..k {
            let b = ctx.mine_real_pow_block_on(vec![tip], vec![]);
            tip = b.header.hash;
            ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("a branch block is valid");
        }
    }
    let extra = ctx.mine_real_pow_block_on(vec![base_hash], vec![]);
    ctx.consensus.validate_and_insert_block(extra).virtual_state_task.await.expect("the extra block is valid");
    assert_eq!(ctx.consensus.get_tips().len(), 3);
    for i in 0..4 {
        let b = ctx.mine_real_pow_block();
        let outputs = b.transactions[0].outputs.len();
        assert!(outputs <= k + 2, "block {i}: the template's coinbase has {outputs} outputs, over the pre-fork cap");
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("the template block is valid");
    }
    assert_eq!(ctx.consensus.get_tips().len(), 1, "every tip is merged within a few blocks");
}

/// Round-2 audit: a history-backfill chunk may not place a block this node already indexes at a
/// different index (it re-pointed a validated block's `index_by_hash`, and a later purge deleted
/// that block's own scan record), nor repeat a block. An honest re-send of an indexed block at its
/// own index is still fine.
#[tokio::test]
async fn backfill_refuses_records_that_collide_with_the_chain_index() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([7u8; 32]).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);
    let mut chain = Vec::new();
    for _ in 0..8 {
        let b = ctx.mine_real_pow_block();
        let h = b.header.hash;
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
        chain.push(h);
    }
    // A linear chain: genesis is index 0, chain[i] is index i + 1.
    let anchor = chain[5];
    let anchor_index = 6u64;
    let validated = ctx.consensus.get_shielded_chain_block_data(chain[7]).unwrap();
    let err = ctx.consensus.backfill_shielded_history(anchor, anchor_index, &[(2, validated.clone())]);
    assert!(err.is_err(), "a validated block may not be re-indexed below the anchor");
    let below = ctx.consensus.get_shielded_chain_block_data(chain[2]).unwrap();
    assert!(
        ctx.consensus.backfill_shielded_history(anchor, anchor_index, &[(3, below.clone()), (2, below.clone())]).is_err(),
        "a chunk repeating a block is refused"
    );
    ctx.consensus.backfill_shielded_history(anchor, anchor_index, &[(3, below)]).expect("a block at its own index is accepted");
    // The validated tip block still resolves at its own index: nothing is above it.
    let above_tip = ctx.consensus.get_shielded_chain_range(chain[7], 4).unwrap().expect("the tip is indexed");
    assert!(above_tip.is_empty(), "the tip's index entry was not re-pointed below the anchor");
}

/// Round-2 audit: for a post-fork pruning point the window entries are the proof, so a peer pair
/// naming a post-fork block (a fake root beside a real window block) must not be seeded, and a named
/// anchor block this node holds no frontier for is judged by its proven window entry only. Also a
/// score lie for a proven block and a broken entry chain.
#[tokio::test]
async fn post_fork_import_trusts_only_the_proven_window() {
    let config = fork_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);
    let mut chain = Vec::new();
    for _ in 0..10 {
        let b = ctx.mine_real_pow_block();
        let h = b.header.hash;
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("every post-fork block validates");
        chain.push(h);
    }
    let vp = ctx.consensus.virtual_processor();
    let mgr = vp.shielded_state_manager_ref();
    let blue_score = |h: Hash| ctx.consensus.get_header(h).unwrap().blue_score;
    let (src, pp, tip) = (chain[2], chain[6], chain[9]);
    let real_root = mgr.own_anchor_of(src).unwrap().expect("src has a frontier");
    let fake_root = [0xEEu8; 32];
    let committed = vp.shielded_state_root_at(pp).unwrap();

    let wire = vp.export_pruning_point_shielded(pp).unwrap().expect("pp exports");
    let mut md = crate::processes::shielded::PruningPointShieldedMetadata::from_wire_bytes(&wire.data).unwrap();
    md.in_window_anchors.push((fake_root, src));
    md.in_window_anchor_source_scores.retain(|(b, _)| *b != src);
    md.in_window_anchor_source_scores.insert(0, (src, 1));
    let wire = kaspa_consensus_core::api::ShieldedExportMetadata { data: md.to_wire_bytes(), nullifier_count: wire.nullifier_count };
    let mut none = std::iter::empty::<Vec<[u8; 32]>>();
    ctx.consensus.import_pruning_point_shielded(pp, wire, Some(committed), &mut none).expect("honest window imports");
    assert!(!mgr.anchor_producer_blocks(&fake_root).unwrap().contains(&src), "a peer pair for a post-fork block is not seeded");
    assert_eq!(mgr.attested_source_blue_score(src).unwrap(), Some(blue_score(src)), "a proven block's score comes from its entry");

    // The node no longer holds src's frontier (as below a fast-synced node's pruning point).
    vp.prune_shielded_snapshots_for_test(src, false);
    assert_eq!(mgr.own_anchor_of(src).unwrap(), None);
    let named = |root: [u8; 32], block: Hash| vp.resolve_shielded_anchor(&root, Some(block.as_bytes()), tip, blue_score(tip), u64::MAX);
    assert!(named(real_root, src).is_final, "the proven entry vouches for the real root");
    assert!(!named(fake_root, src).is_final, "and for nothing else");
    assert!(!named(real_root, Hash::from_bytes([0x77; 32])).is_final, "an unknown named block is refused");
    // A post-fork block with neither a frontier nor a window entry: the producer index (which this
    // node wrote for its own block) must not vouch for it.
    let src2 = chain[3];
    let root2 = mgr.own_anchor_of(src2).unwrap().expect("src2 has a frontier");
    assert!(mgr.anchor_producer_blocks(&root2).unwrap().contains(&src2), "precondition: the producer index names src2");
    vp.prune_shielded_snapshots_for_test(src2, true);
    assert!(!named(root2, src2).is_final, "without its proven entry a post-fork block vouches for nothing");

    // A short chain has only bucket 0, so nothing can sit below its floor; that rule is unit-tested in
    // anchor_window. The chain-link rule is checked here.
    let wire = vp.export_pruning_point_shielded(pp).unwrap().expect("pp exports");
    let mut md = crate::processes::shielded::PruningPointShieldedMetadata::from_wire_bytes(&wire.data).unwrap();
    md.window_entries[1].parent = [0x55; 32];
    assert!(vp.verify_import_binding_versioned(pp, &md, committed).is_err(), "a broken parent link is refused");
}

/// Before the security fork the v0 root does not cover the carried dev balance or the miner slot,
/// so a lying peer could seed either at a pruning point. Where consensus fixes the value (no dev
/// balance from the dev-fee end on; no slot before the fork) the import must refuse anything else,
/// or the first ended block would demand a dev payout no honest block makes and the node wedges.
#[tokio::test]
async fn pre_fork_import_refuses_a_dev_balance_after_the_end_and_any_miner_slot() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.security_fork_activation = ForkActivation::never();
    params.dev_fee_accrual_activation = ForkActivation::always();
    params.dev_fee_payout_interval = 1_000;
    params.dev_fee_end_activation = ForkActivation::new(6);
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);
    let mut chain = Vec::new();
    for _ in 0..12 {
        let b = ctx.mine_real_pow_block();
        chain.push((b.header.hash, b.header.daa_score));
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("valid");
    }
    let vp = ctx.consensus.virtual_processor();
    let check = |pp: Hash| {
        let committed = vp.shielded_state_root_at(pp).unwrap();
        let wire = vp.export_pruning_point_shielded(pp).unwrap().expect("pp exports");
        let md = crate::processes::shielded::PruningPointShieldedMetadata::from_wire_bytes(&wire.data).unwrap();
        (md, committed)
    };
    // Before the end a balance is carried and the honest export re-binds.
    let (before, _) = chain.iter().copied().find(|(_, d)| *d >= 3 && *d < 6).expect("a block before the end");
    let (md, committed) = check(before);
    assert!(md.dev_accrued > 0, "a dev balance is carried before the end");
    vp.verify_import_binding_versioned(before, &md, committed).expect("honest pre-end export re-binds");
    // After the end the honest value is 0; a lying 1 is refused although the v0 root cannot see it.
    let (after, _) = *chain.last().unwrap();
    let (md, committed) = check(after);
    assert_eq!(md.dev_accrued, 0);
    vp.verify_import_binding_versioned(after, &md, committed).expect("honest post-end export re-binds");
    let mut lie = md.clone();
    lie.dev_accrued = 1;
    assert!(vp.verify_import_binding_versioned(after, &lie, committed).is_err(), "a dev balance after the end is refused");
    // No slot exists before the fork.
    let mut lie = md.clone();
    lie.miner_accrual = kaspa_consensus_core::coinbase::MinerAccrual { script_public_key: ctx.miner_data.script_public_key.clone(), amount: 5 };
    assert!(vp.verify_import_binding_versioned(after, &lie, committed).is_err(), "a pre-fork miner slot is refused");
}

/// Security fork, miner accrual end to end through real validated blocks: two miners, a switch and
/// back, and a short payout interval. Every block must validate (the template and the validator
/// build the same coinbase, and the pool-delta check accounts for the carried slot), far fewer miner
/// notes are minted than blocks, and the slot exported at a pruning point re-binds to the committed
/// root while a tampered slot does not.
#[tokio::test]
async fn security_fork_miner_rewards_accrue_and_pay_out_end_to_end() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.security_fork_activation = ForkActivation::always();
    params.miner_accrual_payout_interval = 6;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let script = |seed: u8| {
        let addr = kaspa_shielded_core::wallet::address_bytes_from_seed([seed; 32]).expect("orchard address");
        ScriptPublicKey::new(0, ScriptVec::from_slice(&addr))
    };
    let (a, b) = (script(9), script(10));
    let mut chain = Vec::new();
    let mut miner_notes = 0usize;
    const BLOCKS: usize = 24;
    for i in 0..BLOCKS {
        ctx.miner_data = MinerData::new(if (6..10).contains(&i) { b.clone() } else { a.clone() }, vec![]);
        let blk = ctx.mine_real_pow_block();
        miner_notes += blk.transactions[0].outputs.iter().filter(|o| o.script_public_key == a || o.script_public_key == b).count();
        let h = blk.header.hash;
        ctx.consensus.validate_and_insert_block(blk).virtual_state_task.await.expect("every accrual block validates");
        chain.push(h);
    }
    let vp = ctx.consensus.virtual_processor();
    assert!(miner_notes > 0, "streaks are paid out");
    assert!(miner_notes * 2 < BLOCKS, "far fewer miner notes than blocks ({miner_notes} for {BLOCKS})");

    // A pruning point that carries a non-empty slot exports it, and the slot is bound by the root.
    let pp = chain[..BLOCKS - 3]
        .iter()
        .rev()
        .copied()
        .find(|h| !vp.miner_accrual_at(*h).unwrap().is_empty())
        .expect("some block carries a slot");
    let slot = vp.miner_accrual_at(pp).unwrap();
    let committed = vp.shielded_state_root_at(pp).unwrap();
    let wire = vp.export_pruning_point_shielded(pp).unwrap().expect("pp exports");
    let md = crate::processes::shielded::PruningPointShieldedMetadata::from_wire_bytes(&wire.data).unwrap();
    assert_eq!(md.miner_accrual, slot, "the export carries the slot");
    vp.verify_import_binding_versioned(pp, &md, committed).expect("honest export re-binds");
    let mut tampered = md.clone();
    tampered.miner_accrual.amount += 1;
    assert!(vp.verify_import_binding_versioned(pp, &tampered, committed).is_err(), "a different carried amount is refused");
    let mut tampered = md.clone();
    tampered.miner_accrual.script_public_key = if slot.script_public_key == a { b.clone() } else { a.clone() };
    assert!(vp.verify_import_binding_versioned(pp, &tampered, committed).is_err(), "a different payee is refused");
    let mut tampered = md.clone();
    tampered.miner_accrual = Default::default();
    assert!(vp.verify_import_binding_versioned(pp, &tampered, committed).is_err(), "dropping the slot is refused");
}

/// Dev-fee end through real validated blocks, with dev accrual and the security fork active: before
/// the end the dev fee is paid only on interval crossings; the first block at or past the end pays
/// the carried balance once; afterwards no dev output exists. Every block passes the coinbase and
/// pool-delta checks. Then dishonest miners: an extra dev payout after the end, and a miner reward
/// paid out before its interval, are both refused by consensus.
#[tokio::test]
async fn dev_fee_end_and_forged_coinbases_through_real_blocks() {
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.security_fork_activation = ForkActivation::always();
    params.dev_fee_accrual_activation = ForkActivation::always();
    params.dev_fee_payout_interval = 4;
    params.miner_accrual_payout_interval = 1_000;
    params.dev_fee_end_activation = ForkActivation::new(10);
    let dev_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&params.dev_fee_recipient.unwrap()));
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).expect("orchard address");
    let miner_spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr));
    ctx.miner_data = MinerData::new(miner_spk.clone(), vec![]);

    let mut dev_notes = Vec::new(); // (daa, value)
    let mut prev_daa = 0u64;
    for _ in 0..24 {
        let b = ctx.mine_real_pow_block();
        let daa = b.header.daa_score;
        for o in b.transactions[0].outputs.iter().filter(|o| o.script_public_key == dev_spk) {
            dev_notes.push((daa, prev_daa, o.value));
        }
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("every block validates across the dev-fee end");
        prev_daa = daa;
    }
    assert!(!dev_notes.is_empty(), "the dev fee was paid before the end");
    let at_or_after: Vec<_> = dev_notes.iter().filter(|(d, _, _)| *d >= 10).collect();
    assert_eq!(at_or_after.len(), 1, "exactly one final dev note at or after the end: {dev_notes:?}");
    assert!(at_or_after[0].1 < 10, "and it is in the first block past the end");
    for (d, pd, _) in dev_notes.iter().filter(|(d, _, _)| *d < 10) {
        assert!(d / 4 > pd / 4, "before the end, dev notes only on interval crossings (daa {d})");
    }

    // A dishonest miner adds a dev payout after the end (taking it from nowhere).
    let forged = ctx.mine_real_pow_block_tampering_coinbase(|cb| {
        cb.outputs.push(kaspa_consensus_core::tx::TransactionOutput::new(1_000, dev_spk.clone()));
    });
    let r = ctx.consensus.validate_and_insert_block(forged).virtual_state_task.await;
    assert!(
        r.is_err() || matches!(r, Ok(kaspa_consensus_core::blockstatus::BlockStatus::StatusDisqualifiedFromChain)),
        "an extra dev payout after the end must be refused, got {r:?}"
    );
    // A dishonest miner pays itself its accrued reward early (the slot is not due until DAA 1,000).
    let early = ctx.mine_real_pow_block_tampering_coinbase(|cb| {
        cb.outputs.push(kaspa_consensus_core::tx::TransactionOutput::new(5_000_000, miner_spk.clone()));
    });
    let r = ctx.consensus.validate_and_insert_block(early).virtual_state_task.await;
    assert!(
        r.is_err() || matches!(r, Ok(kaspa_consensus_core::blockstatus::BlockStatus::StatusDisqualifiedFromChain)),
        "an early miner payout must be refused, got {r:?}"
    );
    // And the honest chain keeps going.
    let b = ctx.mine_real_pow_block();
    ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("honest chain continues");
}

/// Security fork: a ZKas block whose coinbase carries a merge-mining commitment is invalid, so a
/// ZKas block can no longer serve as the aux parent of another ZKas block.
#[tokio::test]
async fn security_fork_rejects_a_coinbase_carrying_a_merge_mining_commitment() {
    use kaspa_consensus_core::auxpow::AuxPow;
    let config = fork_config();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).expect("orchard address");
    let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr));
    ctx.miner_data = MinerData::new(spk.clone(), vec![]);
    for _ in 0..3 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
    }
    for extra in [AuxPow::embed_commitment(&[], Hash::from_u64_word(7), &[]), AuxPow::embed_commitment_v1(&[], Hash::from_u64_word(7), &[])] {
        ctx.miner_data = MinerData::new(spk.clone(), extra);
        let p = ctx.mine_real_pow_block();
        let verdict = ctx.consensus.validate_and_insert_block(p).virtual_state_task.await;
        assert!(verdict.is_err(), "a post-fork ZKas coinbase carrying a merge-mining commitment must be rejected");
    }
}

/// Round-2 audit: the own-coinbase commitment ban starts `2 * finality_depth` before the fork. Starting
/// at the fork let a pre-fork block A carry the bound commitment of a post-fork block B, be mined
/// natively, and then serve as B's aux parent: one solution, two blocks. Before the lead a commitment
/// is still accepted (the rule is unchanged for history); inside it, refused.
#[tokio::test]
async fn coinbase_commitment_ban_starts_two_finality_depths_before_the_fork() {
    use kaspa_consensus_core::auxpow::AuxPow;
    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.security_fork_activation = ForkActivation::new(2 * params.finality_depth() + 4);
    assert_eq!(params.coinbase_commitment_ban_activation().daa_score(), 4);
    assert!(!ForkActivation::never().early_by(1).is_active(u64::MAX - 1), "never stays never");
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.shielded_anchor_depth = 1;
        })
        .build();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).expect("orchard address");
    let spk = ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr));
    let tagged = MinerData::new(spk.clone(), AuxPow::embed_commitment_v1(&[], Hash::from_u64_word(7), &[]));
    let mut accepted_before = false;
    let mut refused_inside = false;
    for _ in 0..8 {
        ctx.miner_data = tagged.clone();
        let p = ctx.mine_real_pow_block();
        let daa = p.header.daa_score;
        let verdict = ctx.consensus.validate_and_insert_block(p).virtual_state_task.await;
        if daa < 4 {
            assert!(verdict.is_ok(), "before the lead a commitment is accepted as it always was (daa {daa})");
            accepted_before = true;
            continue;
        }
        assert!(verdict.is_err(), "inside the lead a ZKas coinbase carrying a commitment is refused (daa {daa})");
        refused_inside = true;
        ctx.miner_data = MinerData::new(spk.clone(), vec![]);
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("an untagged block is fine");
    }
    assert!(accepted_before && refused_inside);
}

/// Security fork, end to end with a REAL proven spend: after the activation a spend must name its
/// anchor block. Unnamed: the carrying block is invalid (format rule). Named but wrong block: the
/// spend is dropped (the named block did not produce the root) and the block stays valid. Named
/// correctly: applied.
#[tokio::test]
async fn security_fork_spends_must_name_their_anchor_block() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.dev_fee_recipient = None;
    params.security_fork_activation = ForkActivation::always();
    // This test is about anchor naming and spends a block's own coinbase note. A payout interval of
    // one flushes the miner accrual slot every block, so each block still mints its reward as one
    // note exactly as before the fork (accrual itself is covered by its own end-to-end test).
    params.miner_accrual_payout_interval = 1;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.finality_depth = 5;
            p.blockrate.shielded_anchor_depth = 5;
        })
        .build();
    let net = config.genesis.hash.as_bytes();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);

    let mut block1 = None;
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
        block1 = Some(b);
    }
    let block1 = block1.unwrap();
    let cb = &block1.transactions[0];
    let (cb_txid, note_value) = (cb.id(), cb.outputs[0].value);
    let mut later = Vec::new();
    for _ in 0..6 {
        let b = ctx.mine_real_pow_block();
        later.push(b.header.hash);
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
    }
    let recipient_addr = kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap();
    let spend = |anchor_block: Option<Hash>| {
        let mut tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
        let tx_ctx = tx.shielded_sighash_context();
        tx.payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend_anchored(
            miner_seed,
            cb_txid.as_bytes(),
            0,
            note_value,
            recipient_addr,
            note_value - 2_000,
            &net,
            &tx_ctx,
            anchor_block.map(|h| h.as_bytes()),
        )
        .expect("wallet builds a real spend bundle");
        tx.finalize();
        tx
    };

    // 1. Unnamed after the fork: the carrying block is invalid.
    // Injected behind the template validator, which would never include it.
    let bad = ctx.mine_real_pow_block_injecting(vec![spend(None)]);
    let verdict = ctx.consensus.validate_and_insert_block(bad).virtual_state_task.await;
    assert!(
        matches!(verdict, Err(_) | Ok(BlockStatus::StatusDisqualifiedFromChain)),
        "an unnamed spend after the fork invalidates its block: {verdict:?}"
    );

    // 2. Named, but the named block (a later block) did not produce block 1's root: dropped, block valid.
    let wrong = spend(Some(later[0]));
    let wrong_id = wrong.id();
    let b = ctx.mine_real_pow_block_with(vec![wrong]);
    ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("the block itself stays valid");
    let child = ctx.mine_real_pow_block();
    let child_hash = child.header.hash;
    ctx.consensus.validate_and_insert_block(child).virtual_state_task.await.unwrap();
    let applied = ctx.consensus.get_shielded_chain_block_data(child_hash).unwrap();
    assert!(!applied.accepted_txids.contains(&wrong_id), "a spend naming the wrong anchor block is not applied");

    // 3. Named correctly: applied.
    let good = spend(Some(block1.header.hash));
    let good_id = good.id();
    let b = ctx.mine_real_pow_block_with(vec![good]);
    ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.expect("valid");
    let child = ctx.mine_real_pow_block();
    let child_hash = child.header.hash;
    ctx.consensus.validate_and_insert_block(child).virtual_state_task.await.unwrap();
    let applied = ctx.consensus.get_shielded_chain_block_data(child_hash).unwrap();
    assert!(applied.accepted_txids.contains(&good_id), "a correctly named spend is applied");
}

/// Before the fork the anchor-block field is not part of the format: a named spend invalidates its
/// block, so nobody can use the field early and split un-upgraded nodes.
#[tokio::test]
async fn named_anchor_block_is_refused_before_the_fork() {
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_core::tx::TX_VERSION_SHIELDED;

    let mut params = MAINNET_PARAMS.clone();
    params.shielded_coinbase = true;
    params.dev_fee_recipient = None;
    let config = ConfigBuilder::new(params)
        .edit_consensus_params(|p| {
            p.genesis.bits = 0x207fffff;
            p.blockrate.finality_depth = 5;
            p.blockrate.shielded_anchor_depth = 5;
        })
        .build();
    let net = config.genesis.hash.as_bytes();
    let mut ctx = TestContext::new(TestConsensus::new(&config));
    let miner_seed = [7u8; 32];
    let miner_addr = kaspa_shielded_core::wallet::address_bytes_from_seed(miner_seed).expect("orchard address");
    ctx.miner_data = MinerData::new(ScriptPublicKey::new(0, ScriptVec::from_slice(&miner_addr)), vec![]);
    let mut block1 = None;
    for _ in 0..2 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b.clone()).virtual_state_task.await.unwrap();
        block1 = Some(b);
    }
    let block1 = block1.unwrap();
    let cb = &block1.transactions[0];
    for _ in 0..6 {
        let b = ctx.mine_real_pow_block();
        ctx.consensus.validate_and_insert_block(b).virtual_state_task.await.unwrap();
    }
    let mut tx = Transaction::new(TX_VERSION_SHIELDED, vec![], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let tx_ctx = tx.shielded_sighash_context();
    tx.payload = kaspa_shielded_core::wallet::build::build_singleleaf_coinbase_spend_anchored(
        miner_seed,
        cb.id().as_bytes(),
        0,
        cb.outputs[0].value,
        kaspa_shielded_core::wallet::address_bytes_from_seed([9u8; 32]).unwrap(),
        cb.outputs[0].value - 2_000,
        &net,
        &tx_ctx,
        Some(block1.header.hash.as_bytes()),
    )
    .unwrap();
    tx.finalize();
    let b = ctx.mine_real_pow_block_injecting(vec![tx]);
    let verdict = ctx.consensus.validate_and_insert_block(b).virtual_state_task.await;
    assert!(
        matches!(verdict, Err(_) | Ok(BlockStatus::StatusDisqualifiedFromChain)),
        "a named anchor block before the fork invalidates its block: {verdict:?}"
    );
}
