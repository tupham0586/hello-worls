//! Node - Escrow.

//
// MIT License
//
// Copyright (c) 2018 Stegos AG
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

use crate::error::BlockchainError;
use crate::mvcc::MultiVersionedMap;
use crate::output::Output;
use log::*;
use serde_derive::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use stegos_crypto::curve1174;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;

#[derive(Debug, Clone, PartialEq, Eq, Ord, PartialOrd)]
struct EscrowKey {
    validator_pkey: pbc::PublicKey,
    output_hash: Hash,
}

#[derive(Debug, Clone)]
struct EscrowValue {
    wallet_pkey: curve1174::PublicKey,
    active_until_epoch: u64,
    amount: i64,
}

use crate::LSN;
type EscrowMap = MultiVersionedMap<EscrowKey, EscrowValue, LSN>;

#[derive(Debug, Clone)]
pub struct Escrow {
    /// Stakes.
    escrow: EscrowMap,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EscrowInfo {
    pub validators: Vec<ValidatorInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub network_pkey: pbc::PublicKey,
    pub active_stake: i64,
    pub expired_stake: i64,
    pub stakes: Vec<StakeInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct StakeInfo {
    pub utxo: Hash,
    pub wallet_pkey: curve1174::PublicKey,
    pub active_until_epoch: u64,
    pub is_active: bool,
    pub amount: i64,
}

impl Escrow {
    ///
    /// Create a new escrow.
    pub(crate) fn new() -> Self {
        let set = EscrowMap::new();
        Escrow { escrow: set }
    }

    ///
    /// Stake money into escrow.
    ///
    pub(crate) fn stake(
        &mut self,
        lsn: LSN,
        validator_pkey: pbc::PublicKey,
        wallet_pkey: curve1174::PublicKey,
        output_hash: Hash,
        epoch: u64,
        stakes_epoch: u64,
        amount: i64,
    ) {
        let active_until_epoch = epoch + stakes_epoch;
        let key = EscrowKey {
            validator_pkey,
            output_hash,
        };
        let value = EscrowValue {
            wallet_pkey,
            active_until_epoch,
            amount,
        };

        if let Some(v) = self.escrow.insert(lsn, key, value) {
            panic!(
                "Stake already exists: validator={}, utxo={}, amount={}",
                &validator_pkey, &output_hash, v.amount
            );
        }

        let (active_balance, expired_balance) = self.get(&validator_pkey, epoch);
        debug!(
            "Staked: utxo={}, validator={}, amount={}, active_until_epoch={}, active_balance={}, expired_balance={}",
            output_hash, &validator_pkey, amount, active_until_epoch, active_balance, expired_balance
        );
    }

    ///
    /// Unstake money from the escrow.
    ///
    pub(crate) fn unstake(
        &mut self,
        lsn: LSN,
        validator_pkey: pbc::PublicKey,
        output_hash: Hash,
        epoch: u64,
    ) {
        let key = EscrowKey {
            validator_pkey,
            output_hash,
        };
        let val = self.escrow.remove(lsn, &key).expect("stake exists");

        let (active_balance, expired_balance) = self.get(&validator_pkey, epoch);
        debug!(
            "Unstaked: utxo={}, validator={}, amount={}, active_balance={}, expired_balance={}",
            output_hash, validator_pkey, val.amount, active_balance, expired_balance
        );
    }

    ///
    /// Get staked value for validator.
    ///
    /// Returns (active_balance, expired_balance) stake.
    ///
    pub fn get(&self, validator_pkey: &pbc::PublicKey, epoch: u64) -> (i64, i64) {
        let (hash_min, hash_max) = Hash::bounds();
        let key_min = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_min,
        };
        let key_max = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_max,
        };

        let mut active_balance: i64 = 0;
        let mut expired_balance: i64 = 0;
        for (key, value) in self.escrow.range(&key_min..=&key_max) {
            assert_eq!(&key.validator_pkey, validator_pkey);
            if value.active_until_epoch >= epoch {
                active_balance += value.amount;
            } else {
                expired_balance += value.amount;
            }
        }

        (active_balance, expired_balance)
    }

    ///
    /// Returns list of utxos for specific validator.
    ///
    pub fn staker_outputs(&self, validator_pkey: &pbc::PublicKey, epoch: u64) -> (Vec<Hash>, i64) {
        let (hash_min, hash_max) = Hash::bounds();
        let key_min = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_min,
        };
        let key_max = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_max,
        };

        let mut result = Vec::new();
        let mut stake = 0;
        for (key, value) in self.escrow.range(&key_min..=&key_max) {
            assert_eq!(&key.validator_pkey, validator_pkey);
            if value.active_until_epoch >= epoch {
                stake += value.amount;
                result.push(key.output_hash)
            }
        }

        (result, stake)
    }

    ///
    /// Return a wallet key by network key.
    ///
    pub fn wallet_by_network_key(
        &self,
        validator_pkey: &pbc::PublicKey,
    ) -> Option<curve1174::PublicKey> {
        let (hash_min, hash_max) = Hash::bounds();
        let key_min = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_min,
        };
        let key_max = EscrowKey {
            validator_pkey: validator_pkey.clone(),
            output_hash: hash_max,
        };
        self.escrow
            .range(&key_min..=&key_max)
            .next()
            .map(|(_k, v)| v.wallet_pkey)
    }

    ///
    /// Get all staked values of all validators.
    /// Filter out stakers with stake lower than min_stake_amount.
    ///
    pub fn get_stakers_majority(
        &self,
        epoch: u64,
        min_stake_amount: i64,
    ) -> Vec<(pbc::PublicKey, i64)> {
        let mut stakes: BTreeMap<pbc::PublicKey, i64> = BTreeMap::new();
        for (k, v) in self.escrow.iter() {
            if v.active_until_epoch < epoch {
                // Skip expired stakes.
                continue;
            }
            let entry = stakes.entry(k.validator_pkey).or_insert(0);
            *entry += v.amount;
        }

        // filter out validators with low stake.
        stakes
            .into_iter()
            .filter(|(_, amount)| *amount >= min_stake_amount)
            .collect()
    }

    /// Validate that staker didn't try to spent locked stake.
    /// Validate that staker has only one key.
    /// # Arguments
    ///
    /// * - `inputs` - UTXOs referred by self.txins, in the same order as in self.txins.
    ///
    pub fn validate_stakes<'a, OutputIter>(
        &self,
        inputs: OutputIter,
        outputs: OutputIter,
        epoch: u64,
    ) -> Result<(), BlockchainError>
    where
        OutputIter: Iterator<Item = (&'a Output)>,
    {
        let mut staking_balance: HashMap<pbc::PublicKey, i64> = HashMap::new();
        for input in inputs {
            match input {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    // Update staking balance.
                    let stake = staking_balance.entry(o.validator).or_insert(0);
                    *stake -= o.amount;
                }
            }
        }
        for output in outputs {
            match output {
                Output::PaymentOutput(_o) => {}
                Output::PublicPaymentOutput(_o) => {}
                Output::StakeOutput(o) => {
                    if let Some(wallet) = self.wallet_by_network_key(&o.validator) {
                        if wallet != o.recipient {
                            let utxo_hash = Hash::digest(output);
                            return Err(BlockchainError::StakeOutputWithDifferentWalletKey(
                                wallet,
                                o.recipient,
                                utxo_hash,
                            )
                            .into());
                        }
                    }
                    // Update staking balance.
                    let stake = staking_balance.entry(o.validator).or_insert(0);
                    *stake += o.amount;
                }
            };
        }

        for (validator_pkey, balance) in &staking_balance {
            let (active_balance, expired_balance) = self.get(validator_pkey, epoch);
            let expected_balance = active_balance + expired_balance + balance;
            if expected_balance < active_balance {
                return Err(BlockchainError::StakeIsLocked(
                    *validator_pkey,
                    expected_balance,
                    active_balance,
                ));
            }
        }

        Ok(())
    }

    /// Returns an object that represent printable part of the state.
    pub fn info(&self, epoch: u64) -> EscrowInfo {
        let mut validators: HashMap<pbc::PublicKey, ValidatorInfo> = HashMap::new();
        for (k, v) in self.escrow.iter() {
            let entry = validators
                .entry(k.validator_pkey.clone())
                .or_insert(ValidatorInfo {
                    network_pkey: k.validator_pkey.clone(),
                    stakes: Default::default(),
                    active_stake: Default::default(),
                    expired_stake: Default::default(),
                });
            let is_active = v.active_until_epoch >= epoch;
            let stake = StakeInfo {
                utxo: k.output_hash,
                wallet_pkey: v.wallet_pkey,
                active_until_epoch: v.active_until_epoch,
                is_active,
                amount: v.amount,
            };
            (*entry).stakes.push(stake);
            if is_active {
                (*entry).active_stake += v.amount;
            } else {
                (*entry).expired_stake += v.amount;
            }
        }
        let mut validators: Vec<ValidatorInfo> = validators.into_iter().map(|(_k, v)| v).collect();
        validators.sort_by_key(|x| -x.active_stake);
        EscrowInfo { validators }
    }

    #[inline]
    pub(crate) fn current_lsn(&self) -> LSN {
        self.escrow.current_lsn()
    }

    #[inline]
    pub fn checkpoint(&mut self) {
        self.escrow.checkpoint();
    }

    #[inline]
    pub(crate) fn rollback_to_lsn(&mut self, to_lsn: LSN) {
        self.escrow.rollback_to_lsn(to_lsn);
    }
}
