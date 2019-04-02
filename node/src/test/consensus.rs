//
// MIT License
//
// Copyright (c) 2019 Stegos AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::time::{start_test, wait};
use super::*;
use crate::*;
use stegos_blockchain::Block;
use stegos_consensus::ConsensusMessageBody;
use stegos_crypto::pbc::secure;

// TODO: re-enable this test after removing VRF
//#[test]
#[allow(dead_code)]
fn basic() {
    const NUM_NODES: usize = 3;
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        let topic = crate::CONSENSUS_TOPIC;
        // Create NUM_NODES.
        let mut cfg: ChainConfig = Default::default();
        cfg.blocks_in_epoch = 2;
        let mut s: Sandbox = Sandbox::new(cfg.clone(), NUM_NODES);
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 2);
        }
        let epoch = s.nodes[0].node_service.chain.epoch();
        let leader_id = 0;

        // Process N monetary blocks.
        let mut height = s.nodes[0].node_service.chain.height();
        for _ in 1..cfg.blocks_in_epoch {
            wait(timer, cfg.tx_wait_timeout);
            s.poll();
            let block: Block = s.nodes[leader_id]
                .network_service
                .get_broadcast(crate::SEALED_BLOCK_TOPIC);
            assert_eq!(block.base_header().height, height);
            for (i, node) in s.nodes.iter_mut().enumerate() {
                if i != leader_id {
                    node.network_service
                        .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
                }
            }
            s.poll();

            height += 1;
            for node in s.nodes.iter() {
                assert_eq!(node.node_service.chain.height(), height);
            }
        }
        let last_block_hash = s.nodes[0].node_service.chain.last_block_hash();

        // TODO: determine who is a leader.

        // Check for a proposal from the leader.
        let proposal: BlockConsensusMessage = s.nodes[0].network_service.get_broadcast(topic);
        debug!("Proposal: {:?}", proposal);
        assert_eq!(proposal.height, height);
        assert_eq!(proposal.epoch, epoch);
        assert_matches!(proposal.body, ConsensusMessageBody::Proposal { .. });

        // Send this proposal to other nodes.
        for node in s.nodes.iter_mut().skip(1) {
            node.network_service
                .receive_broadcast(topic, proposal.clone());
        }
        s.poll();

        // Check for pre-votes.
        let mut prevotes: Vec<BlockConsensusMessage> = Vec::with_capacity(NUM_NODES);
        for node in s.nodes.iter_mut() {
            let prevote: BlockConsensusMessage = node.network_service.get_broadcast(topic);
            assert_eq!(proposal.height, height);
            assert_eq!(proposal.epoch, epoch);
            assert_eq!(proposal.request_hash, proposal.request_hash);
            assert_matches!(prevote.body, ConsensusMessageBody::Prevote { .. });
            prevotes.push(prevote);
        }

        // Send these pre-votes to nodes.
        for i in 0..NUM_NODES {
            for j in 0..NUM_NODES {
                if i != j {
                    s.nodes[i]
                        .network_service
                        .receive_broadcast(topic, prevotes[j].clone());
                }
            }
        }
        s.poll();

        // Check for pre-commits.
        let mut precommits: Vec<BlockConsensusMessage> = Vec::with_capacity(NUM_NODES);
        for node in s.nodes.iter_mut() {
            let precommit: BlockConsensusMessage = node.network_service.get_broadcast(topic);
            assert_eq!(proposal.height, height);
            assert_eq!(proposal.epoch, epoch);
            assert_eq!(proposal.request_hash, proposal.request_hash);
            if let ConsensusMessageBody::Precommit {
                request_hash_sig, ..
            } = precommit.body
            {
                assert!(secure::check_hash(
                    &proposal.request_hash,
                    &request_hash_sig,
                    &node.node_service.keys.network_pkey
                ));
            } else {
                panic!("Invalid packet");
            }
            precommits.push(precommit);
        }

        // Send these pre-commits to nodes.
        for i in 0..NUM_NODES {
            for j in 0..NUM_NODES {
                if i != j {
                    s.nodes[i]
                        .network_service
                        .receive_broadcast(topic, precommits[j].clone());
                }
            }
        }
        s.poll();

        // Receive sealed block.
        let block: Block = s.nodes[0]
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash = Hash::digest(&block);
        assert_eq!(block_hash, proposal.request_hash);
        assert_eq!(block.base_header().height, height);
        assert_eq!(block.base_header().previous, last_block_hash);

        // Send this sealed block to all other nodes expect the last one.
        for node in s.nodes.iter_mut().take(NUM_NODES - 1).skip(1) {
            node.network_service
                .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone());
        }
        s.poll();

        // Check state of (0..NUM_NODES - 1) nodes.
        for node in s.nodes.iter().take(NUM_NODES - 1) {
            assert_eq!(node.node_service.chain.height(), height + 1);
            assert_eq!(node.node_service.chain.epoch(), epoch);
            assert_eq!(node.node_service.chain.last_block_hash(), block_hash);
        }

        // The last node hasn't received sealed block.
        assert_eq!(s.nodes[NUM_NODES - 1].node_service.chain.height(), height);
        assert_eq!(s.nodes[NUM_NODES - 1].node_service.chain.epoch(), epoch);
        assert_eq!(
            s.nodes[NUM_NODES - 1].node_service.chain.last_block_hash(),
            last_block_hash
        );

        // Wait for TX_WAIT_TIMEOUT.
        wait(timer, cfg.key_block_timeout);
        s.nodes[NUM_NODES - 1].poll();

        // Check that the last node has auto-committed the block.
        assert_eq!(
            s.nodes[NUM_NODES - 1].node_service.chain.height(),
            height + 1
        );
        assert_eq!(s.nodes[NUM_NODES - 1].node_service.chain.epoch(), epoch);
        assert_eq!(
            s.nodes[NUM_NODES - 1].node_service.chain.last_block_hash(),
            block_hash
        );

        // Check that the auto-committed block has been sent to the network.
        let block2: Block = s.nodes[NUM_NODES - 1]
            .network_service
            .get_broadcast(crate::SEALED_BLOCK_TOPIC);
        let block_hash2 = Hash::digest(&block2);
        assert_eq!(block_hash, block_hash2);
    });
}

#[test]
fn request_on_timeout() {
    const NUM_NODES: usize = 3;
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        // Create NUM_NODES.
        let mut cfg: ChainConfig = Default::default();
        cfg.blocks_in_epoch = 2;
        let mut s: Sandbox = Sandbox::new(cfg.clone(), NUM_NODES);
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 2);
        }
        let leader_pk = s.nodes[0].node_service.chain.leader();
        let leader_id = s
            .nodes_keychains
            .iter()
            .enumerate()
            .find(|(_id, keys)| leader_pk == keys.network_pkey)
            .map(|(id, _)| id)
            .unwrap();

        // let leader shot his block
        wait(timer, cfg.tx_wait_timeout);
        s.poll();
        // emulate timeout on other nodes, and wait for request
        wait(timer, cfg.micro_block_timeout);
        info!("BEFORE POLL");
        s.poll();
        for (_, node) in s
            .nodes
            .iter_mut()
            .enumerate()
            .filter(|(id, _)| *id != leader_id)
        {
            let _: ChainLoaderMessage = node
                .network_service
                .get_unicast(crate::loader::CHAIN_LOADER_TOPIC, &leader_pk);
        }
    });
}

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] receive 2/3rd of view_change messages.
//
// Asserts that Nodes [B, D, E] go to the next view_change.
#[test]
fn micro_block_view_change() {
    const NUM_NODES: usize = 4;
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        // Create NUM_NODES.
        let mut cfg: ChainConfig = Default::default();
        cfg.blocks_in_epoch = 200;
        let mut s: Sandbox = Sandbox::new(cfg.clone(), NUM_NODES);
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 2);
        }
        let leader_pk = s.nodes[0].node_service.chain.leader();
        // let leader shot his block
        wait(timer, cfg.tx_wait_timeout);
        s.poll();
        // emulate timeout on other nodes, and wait for request
        wait(timer, cfg.micro_block_timeout);
        info!("PARTITION BEGIN");
        s.poll();
        // emulate dead leader for other nodes
        {
            for node in s.iter_except(&[leader_pk]) {
                assert_eq!(node.node_service.chain.view_change(), 0);
                // skip chain loader message
                let _: ChainLoaderMessage = node
                    .network_service
                    .get_unicast(crate::loader::CHAIN_LOADER_TOPIC, &leader_pk);
            }

            let mut msgs = Vec::new();
            for node in s.iter_except(&[leader_pk]) {
                let id = node.get_id();
                let chain = node
                    .node_service
                    .optimistic
                    .current_chain(&node.node_service.chain);
                let msg =
                    ViewChangeMessage::new(chain, id as u32, &node.node_service.keys.network_skey);
                msgs.push(msg);
            }

            assert_eq!(msgs.len(), 3);

            info!("BROADCAST VIEW_CHANGES");
            for node in s.iter_except(&[leader_pk]) {
                for msg in &msgs {
                    node.network_service
                        .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
                }
            }
            s.poll();
            for node in s.iter_except(&[leader_pk]) {
                // every node should go to the next view_change, after receiving majority of msgs.
                // This assert can fail in case of bad distributions, if leader has > 1/3 slots_count.
                if node.node_service.chain.select_leader(1) == node.node_service.keys.network_pkey {
                    // If node was leader, they have produced monetary block,
                    assert_eq!(node.node_service.chain.view_change(), 2);
                } else {
                    assert_eq!(node.node_service.chain.view_change(), 1);
                }
            }
        }
    });
}

// CASE partition:
// Nodes [A, B, C, D]
//
// 1. Node A leader of view_change 1, didn't broadcast micro block (B1) to [B,C,D]
// 2. Nodes [B, C, D] go to the next view_change 2
// 2.1. Node B become leader of view_change 2, and broadcast new block (B2).
// 3. Nodes [A,C,D] Receive block (B2)
//
// Asserts that Nodes [A, B, D, E] has last block B2, and same height().

#[test]
fn micro_block_from_future_with_proof() {
    const NUM_NODES: usize = 4;
    use log::Level;
    let _ = simple_logger::init_with_level(Level::Trace);
    start_test(|timer| {
        // Create NUM_NODES.
        let mut cfg: ChainConfig = Default::default();
        cfg.blocks_in_epoch = 2000;
        let mut s: Sandbox = Sandbox::new(cfg.clone(), NUM_NODES);
        s.poll();
        for node in s.nodes.iter() {
            assert_eq!(node.node_service.chain.height(), 2);
        }

        let leader_pk = s.nodes[0].node_service.chain.leader();
        let mut starting_view_changes = 0;

        for _ in 0..(cfg.blocks_in_epoch - 2) {
            if s.nodes[0]
                .node_service
                .chain
                .select_leader(starting_view_changes + 1)
                != s.nodes[0].node_service.chain.leader()
            {
                break;
            }
            wait(timer, cfg.tx_wait_timeout);
            s.skip_monetary_block();
            starting_view_changes += 1;
        }

        wait(timer, cfg.tx_wait_timeout);
        s.poll();
        wait(timer, cfg.micro_block_timeout);
        info!("======= PARTITION BEGIN =======");
        s.poll();
        // emulate dead leader for other nodes
        {
            for node in s.iter_except(&[leader_pk]) {
                assert_eq!(node.node_service.chain.view_change(), starting_view_changes);
                // skip chain loader message
                let _: ChainLoaderMessage = node
                    .network_service
                    .get_unicast(crate::loader::CHAIN_LOADER_TOPIC, &leader_pk);
            }

            let mut msgs = Vec::new();
            for node in s.iter_except(&[leader_pk]) {
                let msg: ViewChangeMessage = node.network_service.get_broadcast(VIEW_CHANGE_TOPIC);
                msgs.push(msg);
            }
            assert_eq!(msgs.len(), 3);

            let new_leader = s.nodes[0]
                .node_service
                .chain
                .select_leader(starting_view_changes + 1);
            let new_leader_node = s.node(&new_leader).unwrap();
            // new leader receive all view change messages and produce new block.
            // each node should accept new block.

            info!("======= BROADCAST VIEW_CHANGES =======");
            for msg in &msgs {
                new_leader_node
                    .network_service
                    .receive_broadcast(crate::VIEW_CHANGE_TOPIC, msg.clone())
            }
            new_leader_node.poll();

            info!("======= BROADCAST BLOCK =======");
            let block: Block = new_leader_node
                .network_service
                .get_broadcast(crate::SEALED_BLOCK_TOPIC);

            assert_eq!(block.base_header().view_change, starting_view_changes + 1);
            // broadcast block to other nodes.
            for node in s.iter_except(&[new_leader]) {
                node.network_service
                    .receive_broadcast(crate::SEALED_BLOCK_TOPIC, block.clone())
            }
            s.poll();
            // after this each node should go to the current block

            let last_block_hash = Hash::digest(&block);
            // skip next leader, because it can immediately produce next block,
            // and go to the next view_change.
            let last_winner = s.nodes[0]
                .node_service
                .chain
                .select_leader(starting_view_changes + 2);
            for node in s.iter_except(&[leader_pk, last_winner]) {
                assert_eq!(
                    node.node_service.chain.view_change(),
                    starting_view_changes + 2
                );
                assert_eq!(node.node_service.chain.last_block_hash(), last_block_hash);
                assert_eq!(
                    node.node_service.chain.height(),
                    starting_view_changes as u64 + 3
                );
            }
        }
    });
}
