//! Account.

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

#![deny(warnings)]

pub mod api;
mod change;
mod error;
mod metrics;
mod protos;
mod recovery;
mod snowball;
mod storage;
#[cfg(test)]
mod test;
mod transaction;

use self::error::WalletError;
use self::recovery::recovery_to_account_skey;
use self::snowball::{Snowball, SnowballOutput};
use self::storage::*;
use self::transaction::*;
use api::*;
use failure::{bail, Error};
use futures::future::IntoFuture;
use futures::sync::{mpsc, oneshot};
use futures::{task, Async, Future, Poll, Stream};
use log::*;
use std::collections::HashMap;
use std::fs;
use std::mem;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::{pbc, scc};
use stegos_keychain as keychain;
use stegos_keychain::keyfile::{load_account_pkey, write_account_pkey, write_account_skey};
use stegos_keychain::KeyError;
use stegos_network::Network;
use stegos_node::NodeNotification;
use stegos_node::TransactionStatus;
use stegos_node::{Node, NodeRequest, NodeResponse};
use tokio::runtime::TaskExecutor;
use tokio_timer::{clock, Interval};

const STAKE_FEE: i64 = 0;
const RESEND_TX_INTERVAL: Duration = Duration::from_secs(2 * 60);
const PENDING_UTXO_TIME: Duration = Duration::from_secs(5 * 60);
const CHECK_PENDING_UTXO: Duration = Duration::from_secs(10);

///
/// Events.
///
#[derive(Debug)]
enum AccountEvent {
    //
    // Public API.
    //
    Subscribe {
        tx: mpsc::UnboundedSender<AccountNotification>,
    },
    Request {
        request: AccountRequest,
        tx: oneshot::Sender<AccountResponse>,
    },
}

struct UnsealedAccountService {
    //
    // Config
    //
    /// Path to RocksDB directory.
    database_dir: PathBuf,
    /// Path to account secret key.
    account_skey_file: PathBuf,
    /// Path to account public key.
    account_pkey_file: PathBuf,
    /// Account Secret Key.
    account_skey: scc::SecretKey,
    /// Account Public Key.
    account_pkey: scc::PublicKey,
    /// Network Secret Key.
    network_skey: pbc::SecretKey,
    /// Network Public Key.
    network_pkey: pbc::PublicKey,
    /// Lifetime of stake.
    stake_epochs: u64,
    /// Maximum allowed count of input UTXOs (from Node config)
    max_inputs_in_tx: usize,

    //
    // Current state
    //
    /// Current Epoch.
    epoch: u64,
    /// Time of last macro block.
    last_macro_block_timestamp: Timestamp,
    /// Faciliator's PBC public key
    facilitator_pkey: pbc::PublicKey,

    /// Unspent Payment UXTO.
    // Store time in Instant, to be more compatible with tokio-timer.
    payments: HashMap<Hash, PaymentValue>,
    /// List of pending utxos.
    pending_payments: HashMap<Hash, PendingOutput>,
    /// Unspent Payment UXTO.
    public_payments: HashMap<Hash, PublicPaymentOutput>,
    /// Unspent Stake UTXO.
    stakes: HashMap<Hash, StakeValue>,
    /// Persistent part of the state.
    account_log: AccountLog,

    /// Network API (shared).
    network: Network,
    /// Node API (shared).
    node: Node,
    /// Resend timeout.
    resend_tx: Interval,

    /// Check for pending utxos.
    check_pending_utxos: Interval,

    //
    // Snowball state (owned)
    //
    snowball: Option<(Snowball, oneshot::Sender<AccountResponse>)>,
    //
    // Response from mempool about transaction.
    //
    transaction_response: Option<oneshot::Receiver<NodeResponse>>,

    //
    // Api subscribers
    //
    /// Triggered when state has changed.
    subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,

    //
    // Events source
    //
    /// Recovery status.
    recovery_rx: Option<oneshot::Receiver<NodeResponse>>,
    /// API Requests.
    events: mpsc::UnboundedReceiver<AccountEvent>,
    /// Notifications from node.
    node_notifications: mpsc::UnboundedReceiver<NodeNotification>,
}

impl UnsealedAccountService {
    /// Create a new account.
    fn new(
        database_dir: PathBuf,
        account_skey_file: PathBuf,
        account_pkey_file: PathBuf,
        account_skey: scc::SecretKey,
        account_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        max_inputs_in_tx: usize,
        subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
        events: mpsc::UnboundedReceiver<AccountEvent>,
    ) -> Self {
        info!("My account key: {}", String::from(&account_pkey));
        debug!("My network key: {}", network_pkey.to_hex());

        //
        // State.
        //
        let epoch = 0;
        let payments = HashMap::new();
        let pending_payments = HashMap::new();
        let facilitator_pkey: pbc::PublicKey = pbc::PublicKey::dum();

        let public_payments = HashMap::new();
        let stakes: HashMap<Hash, StakeValue> = HashMap::new();
        let snowball = None;

        let last_macro_block_timestamp = Timestamp::UNIX_EPOCH;

        let account_log = AccountLog::open(&database_dir);
        let transaction_response = None;
        let resend_tx = Interval::new(clock::now(), RESEND_TX_INTERVAL);
        let check_pending_utxos = Interval::new(clock::now(), CHECK_PENDING_UTXO);
        //
        // Recovery.
        //
        let recovery_request = NodeRequest::RecoverAccount {
            account_skey: account_skey.clone(),
            account_pkey: account_pkey.clone(),
        };
        let recovery_rx = Some(node.request(recovery_request));

        //
        // Notifications from node.
        //

        let node_notifications = node.subscribe();

        UnsealedAccountService {
            database_dir,
            account_skey_file,
            account_pkey_file,
            account_skey,
            account_pkey,
            network_skey,
            network_pkey,
            account_log,
            epoch,
            facilitator_pkey,
            payments,
            pending_payments,
            public_payments,
            stakes,
            resend_tx,
            check_pending_utxos,
            snowball,
            stake_epochs,
            max_inputs_in_tx,
            last_macro_block_timestamp,
            network,
            node,
            subscribers,
            recovery_rx,
            events,
            node_notifications,
            transaction_response,
        }
    }

    /// Send money.
    fn payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        locked_timestamp: Option<Timestamp>,
        with_certificate: bool,
    ) -> Result<PaymentTransactionValue, Error> {
        let data = PaymentPayloadData::Comment(comment);
        let unspent_iter = self
            .payments
            .iter()
            .filter(|(h, _)| self.pending_payments.get(h).is_none())
            .map(|(_, v)| (&v.output, v.amount, v.output.locked_timestamp.clone()));
        let sender = if with_certificate {
            Some(&self.account_skey)
        } else {
            None
        };

        let (inputs, outputs, gamma, extended_outputs, fee) = create_payment_transaction(
            sender,
            &self.account_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            TransactionType::Regular(data.clone()),
            locked_timestamp,
            self.last_macro_block_timestamp,
            self.max_inputs_in_tx,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.account_skey, &inputs, &outputs, &gamma, fee)?;

        let payment_info = PaymentTransactionValue::new_payment(tx.clone(), extended_outputs);

        self.account_log
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        let time = clock::now();
        for input in &tx.txins {
            assert!(self
                .pending_payments
                .insert(
                    *input,
                    PendingOutput {
                        time,
                        snowball_session: false,
                    }
                )
                .is_none());
        }

        let tx: Transaction = tx.into();
        self.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();

        Ok(payment_info)
    }

    /// Send money public.
    fn public_payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        locked_timestamp: Option<Timestamp>,
    ) -> Result<PaymentTransactionValue, Error> {
        let unspent_iter = self
            .payments
            .iter()
            .filter(|(h, _)| self.pending_payments.get(h).is_none())
            .map(|(_, v)| (&v.output, v.amount, v.output.locked_timestamp.clone()));

        let (inputs, outputs, gamma, extended_outputs, fee) = create_payment_transaction(
            Some(&self.account_skey),
            &self.account_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            TransactionType::Public,
            locked_timestamp,
            self.last_macro_block_timestamp,
            self.max_inputs_in_tx,
        )?;

        // Transaction TXINs can generally have different keying for each one
        let tx = PaymentTransaction::new(&self.account_skey, &inputs, &outputs, &gamma, fee)?;
        let payment_info = PaymentTransactionValue::new_payment(tx.clone(), extended_outputs);

        self.account_log
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        let time = clock::now();
        for input in &tx.txins {
            assert!(self
                .pending_payments
                .insert(
                    *input,
                    PendingOutput {
                        time,
                        snowball_session: false,
                    }
                )
                .is_none());
        }

        let tx: Transaction = tx.into();
        self.send_transaction(tx.clone())?;
        metrics::WALLET_CREATEAD_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();

        Ok(payment_info)
    }

    fn get_tx_history(&self, starting_from: Timestamp, limit: u64) -> Vec<LogEntryInfo> {
        self.account_log
            .iter_range(starting_from, limit)
            .map(|(t, e)| e.to_info(t))
            .collect()
    }

    /// Send money using value shuffle.
    fn secure_payment(
        &mut self,
        recipient: &scc::PublicKey,
        amount: i64,
        payment_fee: i64,
        comment: String,
        locked_timestamp: Option<Timestamp>,
    ) -> Result<Snowball, Error> {
        if self.snowball.is_some() {
            return Err(WalletError::SnowballBusy.into());
        }
        let unspent_iter = self
            .payments
            .iter()
            .filter(|(h, _)| self.pending_payments.get(h).is_none())
            .map(|(_, v)| (&v.output, v.amount, v.output.locked_timestamp.clone()));
        let (inputs, outputs, fee) = create_snowball_transaction(
            &self.account_pkey,
            recipient,
            unspent_iter,
            amount,
            payment_fee,
            comment,
            locked_timestamp,
            self.last_macro_block_timestamp,
            snowball::MAX_UTXOS,
        )?;
        assert!(inputs.len() <= snowball::MAX_UTXOS);

        let time = clock::now();
        for (input, _) in &inputs {
            assert!(self
                .pending_payments
                .insert(
                    *input,
                    PendingOutput {
                        time,
                        snowball_session: true,
                    }
                )
                .is_none());
        }

        let snowball = Snowball::new(
            self.account_skey.clone(),
            self.account_pkey.clone(),
            self.network_pkey.clone(),
            self.network.clone(),
            self.node.clone(),
            self.facilitator_pkey.clone(),
            inputs,
            outputs,
            fee,
        );

        metrics::WALLET_CREATEAD_SECURE_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();
        Ok(snowball)
    }

    /// Stake money into the escrow.
    fn stake(&mut self, amount: i64, payment_fee: i64) -> Result<PaymentTransactionValue, Error> {
        let unspent_iter = self
            .payments
            .iter()
            .filter(|(h, _)| self.pending_payments.get(h).is_none())
            .map(|(_, v)| (&v.output, v.amount));
        let tx = create_staking_transaction(
            &self.account_skey,
            &self.account_pkey,
            &self.network_pkey,
            &self.network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.last_macro_block_timestamp,
            self.max_inputs_in_tx,
        )?;
        let payment_info = PaymentTransactionValue::new_stake(tx.clone());

        self.account_log
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        let time = clock::now();
        for input in &tx.txins {
            assert!(self
                .pending_payments
                .insert(
                    *input,
                    PendingOutput {
                        time,
                        snowball_session: false,
                    }
                )
                .is_none());
        }

        self.send_transaction(tx.into())?;
        Ok(payment_info)
    }

    /// Unstake money from the escrow.
    /// NOTE: amount must include PAYMENT_FEE.
    fn unstake(&mut self, amount: i64, payment_fee: i64) -> Result<PaymentTransactionValue, Error> {
        let unspent_iter = self.stakes.values().map(|v| &v.output);
        let tx = create_unstaking_transaction(
            &self.account_skey,
            &self.account_pkey,
            &self.network_pkey,
            &self.network_skey,
            unspent_iter,
            amount,
            payment_fee,
            STAKE_FEE,
            self.last_macro_block_timestamp,
            self.max_inputs_in_tx,
        )?;
        let payment_info = PaymentTransactionValue::new_stake(tx.clone());
        self.send_transaction(tx.into())?;
        Ok(payment_info)
    }

    /// Unstake all of the money from the escrow.
    fn unstake_all(&mut self, payment_fee: i64) -> Result<PaymentTransactionValue, Error> {
        let mut amount: i64 = 0;
        for val in self.stakes.values() {
            amount += val.output.amount;
        }
        self.unstake(amount, payment_fee)
    }

    /// Restake all available stakes (even if not expired).
    fn restake_all(&mut self) -> Result<TransactionInfo, Error> {
        assert_eq!(STAKE_FEE, 0);
        if self.stakes.is_empty() {
            return Err(WalletError::NothingToRestake.into());
        }

        let stakes = self.stakes.values().map(|val| &val.output);
        let tx = create_restaking_transaction(
            &self.account_skey,
            &self.account_pkey,
            &self.network_pkey,
            &self.network_skey,
            stakes,
        )?;
        let tx_hash = Hash::digest(&tx);
        self.send_transaction(tx.into())?;
        Ok(TransactionInfo {
            tx_hash,
            fee: 0,
            outputs: vec![],
            inputs: vec![],
            status: TransactionStatus::Created {},
        })
    }

    /// Cloak all available public outputs.
    fn cloak_all(&mut self, payment_fee: i64) -> Result<PaymentTransactionValue, Error> {
        if self.public_payments.is_empty() {
            return Err(WalletError::NoPublicOutputs.into());
        }

        let public_utxos = self.public_payments.values();
        let tx = create_cloaking_transaction(
            &self.account_skey,
            &self.account_pkey,
            public_utxos,
            payment_fee,
            self.last_macro_block_timestamp,
        )?;

        let info = PaymentTransactionValue::new_cloak(tx.clone());
        self.send_transaction(tx.into())?;
        Ok(info)
    }

    /// Change the password.
    fn change_password(&mut self, new_password: String) -> Result<(), Error> {
        let account_skey_path = Path::new(&self.account_skey_file);
        keychain::keyfile::write_account_skey(
            account_skey_path,
            &self.account_skey,
            &new_password,
        )?;
        Ok(())
    }

    /// Return recovery codes.
    fn get_recovery(&mut self) -> Result<String, Error> {
        Ok(crate::recovery::account_skey_to_recovery(
            &self.account_skey,
        ))
    }

    /// Get actual balance.
    fn balance(&self) -> (i64, i64) {
        let time = Timestamp::now();
        let mut balance: i64 = 0;
        let mut available_balance: i64 = 0;
        for (hash, val) in self.payments.iter() {
            balance += val.amount;

            if let Some(t) = val.output.locked_timestamp {
                if t > time {
                    continue;
                }
            }

            if self.pending_payments.get(hash).is_some() {
                continue;
            }

            available_balance += val.amount;
        }
        (balance, available_balance)
    }

    /// Called when outputs registered and/or pruned.
    fn on_outputs_changed(
        &mut self,
        epoch: u64,
        inputs: HashMap<Hash, Output>,
        outputs: HashMap<Hash, Output>,
    ) {
        let (saved_balance, saved_available_balance) = self.balance();

        // This order is important - first create outputs, then remove inputs.
        // Otherwise it will fail in case of annihilated input/output in a macro block.
        for (output_hash, output) in outputs {
            self.on_output_created(epoch, output_hash, output);
        }
        for (input_hash, input) in inputs {
            self.on_output_pruned(epoch, input_hash, input);
        }

        let (balance, available_balance) = self.balance();

        metrics::WALLET_BALANCES
            .with_label_values(&[&String::from(&self.account_pkey)])
            .set(balance);

        metrics::WALLET_AVALIABLE_BALANCES
            .with_label_values(&[&String::from(&self.account_pkey)])
            .set(available_balance);

        if saved_balance != balance || saved_available_balance != available_balance {
            debug!("Balance changed");
            self.notify(AccountNotification::BalanceChanged {
                balance,
                available_balance,
            });
        }
    }

    /// Called when UTXO is created.
    fn on_output_created(&mut self, epoch: u64, hash: Hash, output: Output) {
        if !output.is_my_utxo(&self.account_skey, &self.account_pkey) {
            return;
        }
        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) =
                    o.decrypt_payload(&self.account_skey)
                {
                    assert!(amount >= 0);
                    info!(
                        "Received: utxo={}, amount={}, data={:?}",
                        hash, amount, data
                    );
                    let value = PaymentValue {
                        output: o,
                        amount,
                        data: data.clone(),
                    };

                    if let Err(e) = self
                        .account_log
                        .push_incomming(Timestamp::now(), value.clone().into())
                    {
                        error!("Error when adding incomming tx = {}", e)
                    }

                    let info = value.to_info(None);
                    let missing = self.payments.insert(hash, value);
                    assert!(missing.is_none());
                    self.notify(AccountNotification::Received(info));
                }
            }
            Output::PublicPaymentOutput(o) => {
                let PublicPaymentOutput { ref amount, .. } = &o;
                assert!(*amount >= 0);
                info!("Received public payment: utxo={}, amount={}", hash, amount);
                let value = o.clone();

                if let Err(e) = self
                    .account_log
                    .push_incomming(Timestamp::now(), value.clone().into())
                {
                    error!("Error when adding incomming tx = {}", e)
                }

                let info = public_payment_info(&value);
                let missing = self.public_payments.insert(hash, value);
                assert!(missing.is_none());
                self.notify(AccountNotification::ReceivedPublic(info));
            }
            Output::StakeOutput(o) => {
                let active_until_epoch = epoch + self.stake_epochs;
                info!(
                    "Staked money to escrow: hash={}, amount={}, active_until_epoch={}",
                    hash, o.amount, active_until_epoch
                );
                let value = StakeValue {
                    output: o,
                    active_until_epoch,
                };

                let info = value.to_info(self.epoch);
                let missing = self.stakes.insert(hash, value);
                assert!(missing.is_none(), "Inconsistent account state");
                self.notify(AccountNotification::Staked(info));
            }
        };
    }

    /// Called when UTXO is spent.
    fn on_output_pruned(&mut self, _epoch: u64, hash: Hash, output: Output) {
        if !output.is_my_utxo(&self.account_skey, &self.account_pkey) {
            return;
        }
        match output {
            Output::PaymentOutput(o) => {
                if let Ok(PaymentPayload { amount, data, .. }) =
                    o.decrypt_payload(&self.account_skey)
                {
                    info!("Spent: utxo={}, amount={}, data={:?}", hash, amount, data);
                    match self.payments.remove(&hash) {
                        Some(value) => {
                            let info = value.to_info(self.pending_payments.get(&hash));
                            self.notify(AccountNotification::Spent(info));
                        }
                        None => panic!("Inconsistent account state"),
                    }
                }
            }
            Output::PublicPaymentOutput(PublicPaymentOutput { amount, .. }) => {
                info!("Spent public payment: utxo={}, amount={}", hash, amount);
                match self.public_payments.remove(&hash) {
                    Some(value) => {
                        let info = public_payment_info(&value);
                        self.notify(AccountNotification::SpentPublic(info));
                    }
                    None => panic!("Inconsistent account state"),
                }
            }
            Output::StakeOutput(o) => {
                info!("Unstaked: utxo={}, amount={}", hash, o.amount);
                match self.stakes.remove(&hash) {
                    Some(value) => {
                        let info = value.to_info(self.epoch);
                        self.notify(AccountNotification::Unstaked(info));
                    }
                    None => panic!("Inconsistent account state"),
                }
            }
        }
    }

    fn send_transaction(&mut self, tx: Transaction) -> Result<(), Error> {
        if self.transaction_response.is_some() {
            bail!(
                "Cannot create new transaction, tx={}, \
                 old transaction stil on the way to mempool.",
                Hash::digest(&tx)
            )
        } else {
            self.transaction_response = Some(self.node.send_transaction(tx.clone()));
            task::current().notify();
        }
        Ok(())
    }

    fn on_epoch_changed(&mut self, epoch: u64, time: Timestamp) {
        self.epoch = epoch;
        self.last_macro_block_timestamp = time;
    }

    fn handle_snowball_transaction(
        &mut self,
        tx: PaymentTransaction,
        is_leader: bool,
    ) -> Result<TransactionInfo, Error> {
        let tx_hash = Hash::digest(&tx);
        metrics::WALLET_PUBLISHED_PAYMENTS
            .with_label_values(&[&String::from(&self.account_pkey)])
            .inc();

        let notify = AccountNotification::SnowballCreated { tx_hash };
        self.notify(notify);

        let payment_info = PaymentTransactionValue::new_vs(tx.clone());

        self.account_log
            .push_outgoing(Timestamp::now(), payment_info.clone())?;

        if is_leader {
            // if I'm leader, then send the completed super-transaction
            // to the blockchain.
            debug!("Sending SuperTransaction to BlockChain");
            self.send_transaction(tx.into())?
        }
        Ok(payment_info.to_info())
    }

    fn on_tx_status(&mut self, tx_hash: Hash, status: TransactionStatus) {
        if let Some(timestamp) = self.account_log.tx_entry(tx_hash) {
            // update persistent info.
            self.account_log
                .update_tx_status(tx_hash, timestamp, status.clone())
                .expect("Cannot update status.");

            // update metrics
            match status {
                TransactionStatus::Committed { .. } | TransactionStatus::Prepared { .. } => {
                    metrics::WALLET_COMMITTED_PAYMENTS
                        .with_label_values(&[&String::from(&self.account_pkey)])
                        .inc();
                }
                TransactionStatus::Rollback { .. } => {
                    metrics::WALLET_COMMITTED_PAYMENTS
                        .with_label_values(&[&String::from(&self.account_pkey)])
                        .dec();
                }
                _ => {}
            }

            let msg = AccountNotification::TransactionStatus { tx_hash, status };
            self.notify(msg);
        } else {
            trace!("Transaction was not found = {}", tx_hash);
        }
    }

    fn on_tx_statuses_changed(&mut self, changes: HashMap<Hash, TransactionStatus>) {
        trace!("Updated mempool event");
        for (tx_hash, status) in changes {
            self.on_tx_status(tx_hash, status)
        }
    }

    fn handle_resend_pending_txs(&mut self) {
        trace!("Handle resend pending transactions");
        let txs: Vec<_> = self.account_log.pending_txs().collect();
        for tx in txs {
            match tx {
                Ok(tx) => {
                    debug!(
                        "Found pending transaction for resending: tx_hash = {}, status = {:?}",
                        Hash::digest(&tx.tx),
                        tx.status
                    );
                    // ignore error.
                    let _ = self.send_transaction(tx.tx.into());
                }
                Err(e) => error!("Error during processing database = {}", e),
            }
        }
    }

    fn handle_check_pending_utxos(&mut self, now: Instant) {
        trace!("Handle check pending utxo transactions");
        let pending = std::mem::replace(&mut self.pending_payments, HashMap::new());
        let mut balance_unlocked = false;
        for (hash, p) in pending {
            if p.time + PENDING_UTXO_TIME <= now {
                trace!("Found outdated pending utxo = {}", hash);
                balance_unlocked = true;
                if p.snowball_session {
                    info!(
                        "Some outputs of snowball are now outdated: snowball_session = {}",
                        hash
                    );
                    warn!("Resetting Snowball on timeout.");
                    self.snowball = None;
                }
            } else {
                assert!(self.pending_payments.insert(hash, p).is_none());
            }
        }

        if !balance_unlocked {
            return;
        }

        // if balance was changed return new balance.

        let (balance, available_balance) = self.balance();
        metrics::WALLET_AVALIABLE_BALANCES
            .with_label_values(&[&String::from(&self.account_pkey)])
            .set(available_balance);
        debug!("Balance changed");
        self.notify(AccountNotification::BalanceChanged {
            balance,
            available_balance,
        });
    }

    fn notify(&mut self, notification: AccountNotification) {
        trace!("Created notification = {:?}", notification);
        self.subscribers
            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
    }
}

impl From<Result<PaymentTransactionValue, Error>> for AccountResponse {
    fn from(r: Result<PaymentTransactionValue, Error>) -> Self {
        match r {
            Ok(info) => AccountResponse::TransactionCreated(info.to_info()),
            Err(e) => AccountResponse::Error {
                error: format!("{}", e),
            },
        }
    }
}

/// This could be used for non PaymentTx.
impl From<Result<TransactionInfo, Error>> for AccountResponse {
    fn from(r: Result<TransactionInfo, Error>) -> Self {
        match r {
            Ok(info) => AccountResponse::TransactionCreated(info),
            Err(e) => AccountResponse::Error {
                error: format!("{}", e),
            },
        }
    }
}

impl From<Vec<LogEntryInfo>> for AccountResponse {
    fn from(log: Vec<LogEntryInfo>) -> Self {
        AccountResponse::HistoryInfo { log }
    }
}

// Event loop.
impl Future for UnsealedAccountService {
    type Item = Option<()>;
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Recovery information from node.
        if let Some(ref mut recovery_rx) = &mut self.recovery_rx {
            match recovery_rx.poll() {
                Ok(Async::Ready(response)) => {
                    self.recovery_rx = None;
                    match response {
                        NodeResponse::AccountRecovered(persistent_state) => {
                            // Recover state.
                            for OutputRecovery { output, epoch, .. } in persistent_state {
                                let output_hash = Hash::digest(&output);
                                self.on_output_created(epoch, output_hash, output);
                            }
                        }
                        NodeResponse::Error { error } => {
                            // Sic: this case is hard to recover.
                            panic!("Failed to recover account: {:?}", error);
                        }
                        _ => unreachable!(),
                    };
                }
                Ok(Async::NotReady) => {
                    return Ok(Async::NotReady);
                }
                Err(_) => panic!("disconnected"),
            }
        }

        if let Some(mut transaction_response) = self.transaction_response.take() {
            match transaction_response.poll().expect("connected") {
                Async::Ready(response) => {
                    match response {
                        NodeResponse::AddTransaction { hash, status } => {
                            // Recover state.
                            self.on_tx_status(hash, status);
                        }
                        NodeResponse::Error { error } => {
                            error!("Failed to get transaction status: {:?}", error);
                        }
                        _ => unreachable!(),
                    };
                }
                Async::NotReady => self.transaction_response = Some(transaction_response),
            }
        }

        loop {
            match self.resend_tx.poll().expect("no errors in timers") {
                Async::Ready(Some(_t)) => self.handle_resend_pending_txs(),
                Async::NotReady => break,
                e => panic!("Error in handling resend tx timer = {:?}", e),
            }
        }

        loop {
            match self
                .check_pending_utxos
                .poll()
                .expect("no errors in timers")
            {
                Async::Ready(Some(t)) => self.handle_check_pending_utxos(t),
                Async::NotReady => break,
                e => panic!("Error in handling check pending utxos timer = {:?}", e),
            }
        }

        if let Some((mut vs, response_sender)) = mem::replace(&mut self.snowball, None) {
            match vs.poll() {
                Ok(Async::Ready(SnowballOutput { tx, is_leader })) => {
                    let response = match self.handle_snowball_transaction(tx, is_leader) {
                        Ok(tx) => AccountResponse::TransactionCreated(tx),
                        Err(e) => {
                            error!("Error during processing snowball transaction = {}", e);
                            AccountResponse::Error {
                                error: e.to_string(),
                            }
                        }
                    };
                    let _ = response_sender.send(response);
                }
                Err((error, inputs)) => {
                    warn!("Error during snowball session error={}.", error);
                    for (input_hash, _input) in inputs {
                        assert!(self.pending_payments.remove(&input_hash).is_some())
                    }
                    let response = AccountResponse::Error {
                        error: error.to_string(),
                    };
                    let _ = response_sender.send(response);
                }
                Ok(Async::NotReady) => {
                    self.snowball = (vs, response_sender).into();
                }
            }
        }

        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    AccountEvent::Request { request, tx } => {
                        let response = match request {
                            AccountRequest::Unseal { password: _ } => AccountResponse::Error {
                                error: "Already unsealed".to_string(),
                            },
                            AccountRequest::Seal {} => {
                                tx.send(AccountResponse::Sealed).ok();
                                // Finish this future.
                                return Ok(Async::Ready(Some(())));
                            }
                            AccountRequest::Payment {
                                recipient,
                                amount,
                                payment_fee,
                                comment,
                                locked_timestamp,
                                with_certificate,
                            } => self
                                .payment(
                                    &recipient,
                                    amount,
                                    payment_fee,
                                    comment,
                                    locked_timestamp,
                                    with_certificate,
                                )
                                .into(),
                            AccountRequest::PublicPayment {
                                recipient,
                                amount,
                                payment_fee,
                                locked_timestamp,
                            } => self
                                .public_payment(&recipient, amount, payment_fee, locked_timestamp)
                                .into(),
                            AccountRequest::Stake {
                                amount,
                                payment_fee,
                            } => self.stake(amount, payment_fee).into(),
                            AccountRequest::Unstake {
                                amount,
                                payment_fee,
                            } => self.unstake(amount, payment_fee).into(),
                            AccountRequest::UnstakeAll { payment_fee } => {
                                self.unstake_all(payment_fee).into()
                            }
                            AccountRequest::RestakeAll {} => self.restake_all().into(),
                            AccountRequest::CloakAll { payment_fee } => {
                                self.cloak_all(payment_fee).into()
                            }
                            AccountRequest::KeysInfo {} => AccountResponse::KeysInfo {
                                account_address: self.account_pkey,
                                network_address: self.network_pkey,
                            },
                            AccountRequest::BalanceInfo {} => {
                                let (balance, available_balance) = self.balance();
                                AccountResponse::BalanceInfo {
                                    balance,
                                    available_balance,
                                }
                            }
                            AccountRequest::UnspentInfo {} => {
                                let epoch = self.epoch;
                                let public_payments: Vec<PublicPaymentInfo> = self
                                    .public_payments
                                    .values()
                                    .map(public_payment_info)
                                    .collect();
                                let payments: Vec<PaymentInfo> = self
                                    .payments
                                    .iter()
                                    .map(|(h, v)| v.to_info(self.pending_payments.get(h)))
                                    .collect();
                                let stakes: Vec<StakeInfo> = self
                                    .stakes
                                    .values()
                                    .map(|value| value.to_info(epoch))
                                    .collect();
                                AccountResponse::UnspentInfo {
                                    public_payments,
                                    payments,
                                    stakes,
                                }
                            }
                            AccountRequest::HistoryInfo {
                                starting_from,
                                limit,
                            } => self.get_tx_history(starting_from, limit).into(),
                            AccountRequest::ChangePassword { new_password } => {
                                match self.change_password(new_password) {
                                    Ok(()) => AccountResponse::PasswordChanged,
                                    Err(e) => AccountResponse::Error {
                                        error: format!("{}", e),
                                    },
                                }
                            }
                            AccountRequest::GetRecovery {} => match self.get_recovery() {
                                Ok(recovery) => AccountResponse::Recovery { recovery },
                                Err(e) => AccountResponse::Error {
                                    error: format!("{}", e),
                                },
                            },
                            AccountRequest::SecurePayment {
                                recipient,
                                amount,
                                payment_fee,
                                comment,
                                locked_timestamp,
                            } => match self.secure_payment(
                                &recipient,
                                amount,
                                payment_fee,
                                comment,
                                locked_timestamp,
                            ) {
                                Ok(snowball) => {
                                    self.notify(AccountNotification::SnowballStarted {});
                                    self.snowball = (snowball, tx).into();
                                    continue;
                                }
                                Err(e) => AccountResponse::Error {
                                    error: format!("{}", e),
                                },
                            },
                        };
                        tx.send(response).ok(); // ignore errors.
                    }
                    AccountEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                },
                Async::Ready(None) => return Ok(Async::Ready(None)),
                Async::NotReady => break,
            }
        }

        loop {
            match self
                .node_notifications
                .poll()
                .expect("all errors are already handled")
            {
                Async::Ready(Some(notification)) => match notification {
                    NodeNotification::NewMicroBlock(block) => {
                        assert!(self.recovery_rx.is_none(), "recovered from the disk");
                        self.on_tx_statuses_changed(block.statuses);
                        self.on_outputs_changed(block.epoch, block.inputs, block.outputs);
                    }
                    NodeNotification::NewMacroBlock(block) => {
                        assert!(self.recovery_rx.is_none(), "recovered from the disk");
                        self.on_tx_statuses_changed(block.statuses);
                        self.on_outputs_changed(block.epoch, block.inputs, block.outputs);
                        self.on_epoch_changed(block.epoch, block.last_macro_block_timestamp);
                        let updated_statuses = self.account_log.finalize_epoch_txs();
                        self.on_tx_statuses_changed(updated_statuses);
                        self.facilitator_pkey = block.facilitator.clone();
                        if let Some((ref mut vs, _)) = &mut self.snowball {
                            vs.change_facilitator(block.facilitator);
                        }
                    }
                    NodeNotification::RollbackMicroBlock(block) => {
                        assert!(self.recovery_rx.is_none(), "recovered from the disk");
                        self.on_tx_statuses_changed(block.statuses);
                        self.on_outputs_changed(block.epoch, block.inputs, block.outputs);
                    }
                    _ => {}
                },
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => break,
            }
        }

        Ok(Async::NotReady)
    }
}

struct SealedAccountService {
    /// Path to database dir.
    database_dir: PathBuf,
    /// Path to account secret key.
    account_skey_file: PathBuf,
    /// Path to account public key.
    account_pkey_file: PathBuf,
    /// Account Public Key.
    account_pkey: scc::PublicKey,
    /// Network Secret Key.
    network_skey: pbc::SecretKey,
    /// Network Public Key.
    network_pkey: pbc::PublicKey,
    /// Lifetime of stake.
    stake_epochs: u64,
    /// Maximum allowed count of input UTXOs
    max_inputs_in_tx: usize,

    /// Network API (shared).
    network: Network,
    /// Node API (shared).
    node: Node,

    //
    // Api subscribers
    //
    subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
    /// Incoming events.
    events: mpsc::UnboundedReceiver<AccountEvent>,
}

impl SealedAccountService {
    fn new(
        database_dir: PathBuf,
        account_skey_file: PathBuf,
        account_pkey_file: PathBuf,
        account_pkey: scc::PublicKey,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        max_inputs_in_tx: usize,
        subscribers: Vec<mpsc::UnboundedSender<AccountNotification>>,
        events: mpsc::UnboundedReceiver<AccountEvent>,
    ) -> Self {
        SealedAccountService {
            database_dir,
            account_skey_file,
            account_pkey_file,
            account_pkey,
            network_skey,
            network_pkey,
            stake_epochs,
            max_inputs_in_tx,
            node,
            network,
            subscribers,
            events,
        }
    }

    fn load_secret_key(&self, password: &str) -> Result<scc::SecretKey, KeyError> {
        let account_skey = keychain::keyfile::load_account_skey(&self.account_skey_file, password)?;

        if let Err(_e) = scc::check_keying(&account_skey, &self.account_pkey) {
            return Err(KeyError::InvalidKeying(
                self.account_skey_file.to_string_lossy().to_string(),
                self.account_pkey_file.to_string_lossy().to_string(),
            ));
        }
        Ok(account_skey)
    }
}

// Event loop.
impl Future for SealedAccountService {
    type Item = Option<scc::SecretKey>;
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    AccountEvent::Request { request, tx } => {
                        let response = match request {
                            AccountRequest::Unseal { password } => {
                                match self.load_secret_key(&password) {
                                    Ok(account_skey) => {
                                        tx.send(AccountResponse::Unsealed).ok(); // ignore errors.
                                                                                 // Finish this future.
                                        return Ok(Async::Ready(Some(account_skey)));
                                    }
                                    Err(e) => AccountResponse::Error {
                                        error: format!("{}", e),
                                    },
                                }
                            }
                            AccountRequest::KeysInfo {} => AccountResponse::KeysInfo {
                                account_address: self.account_pkey,
                                network_address: self.network_pkey,
                            },
                            _ => AccountResponse::Error {
                                error: "Account is sealed".to_string(),
                            },
                        };
                        tx.send(response).ok(); // ignore errors.
                    }
                    AccountEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                },
                Async::Ready(None) => return Ok(Async::Ready(None)),
                Async::NotReady => return Ok(Async::NotReady),
            }
        }
    }
}

enum AccountService {
    Invalid,
    Sealed(SealedAccountService),
    Unsealed(UnsealedAccountService),
}

// Event loop.
impl Future for AccountService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self {
            AccountService::Invalid => unreachable!(),
            AccountService::Sealed(sealed) => match sealed.poll().unwrap() {
                Async::Ready(None) => {
                    debug!("Terminated");
                    return Ok(Async::Ready(()));
                }
                Async::Ready(Some(account_skey)) => {
                    let sealed = match std::mem::replace(self, AccountService::Invalid) {
                        AccountService::Sealed(old) => old,
                        _ => unreachable!(),
                    };
                    info!("Unsealed account: pkey={}", &sealed.account_pkey);
                    let unsealed = UnsealedAccountService::new(
                        sealed.database_dir,
                        sealed.account_skey_file,
                        sealed.account_pkey_file,
                        account_skey,
                        sealed.account_pkey,
                        sealed.network_skey,
                        sealed.network_pkey,
                        sealed.network,
                        sealed.node,
                        sealed.stake_epochs,
                        sealed.max_inputs_in_tx,
                        sealed.subscribers,
                        sealed.events,
                    );
                    std::mem::replace(self, AccountService::Unsealed(unsealed));
                    task::current().notify();
                }
                Async::NotReady => {}
            },
            AccountService::Unsealed(unsealed) => match unsealed.poll().unwrap() {
                Async::Ready(None) => {
                    debug!("Terminated");
                    return Ok(Async::Ready(()));
                }
                Async::Ready(Some(())) => {
                    let unsealed = match std::mem::replace(self, AccountService::Invalid) {
                        AccountService::Unsealed(old) => old,
                        _ => unreachable!(),
                    };
                    info!("Sealed account: pkey={}", &unsealed.account_pkey);
                    let sealed = SealedAccountService::new(
                        unsealed.database_dir,
                        unsealed.account_skey_file,
                        unsealed.account_pkey_file,
                        unsealed.account_pkey,
                        unsealed.network_skey,
                        unsealed.network_pkey,
                        unsealed.network,
                        unsealed.node,
                        unsealed.stake_epochs,
                        unsealed.max_inputs_in_tx,
                        unsealed.subscribers,
                        unsealed.events,
                    );
                    std::mem::replace(self, AccountService::Sealed(sealed));
                    task::current().notify();
                }
                Async::NotReady => {}
            },
        }
        Ok(Async::NotReady)
    }
}

impl AccountService {
    /// Create a new wallet.
    fn new(
        database_dir: &Path,
        account_skey_file: &Path,
        account_pkey_file: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        stake_epochs: u64,
        max_inputs_in_tx: usize,
    ) -> Result<(Self, Account), KeyError> {
        let account_pkey = load_account_pkey(account_pkey_file)?;
        let subscribers: Vec<mpsc::UnboundedSender<AccountNotification>> = Vec::new();
        let (outbox, events) = mpsc::unbounded::<AccountEvent>();
        let service = SealedAccountService::new(
            database_dir.to_path_buf(),
            account_skey_file.to_path_buf(),
            account_pkey_file.to_path_buf(),
            account_pkey,
            network_skey,
            network_pkey,
            network,
            node,
            stake_epochs,
            max_inputs_in_tx,
            subscribers,
            events,
        );
        let service = AccountService::Sealed(service);
        let api = Account { outbox };
        Ok((service, api))
    }
}

#[derive(Debug, Clone)]
struct Account {
    outbox: mpsc::UnboundedSender<AccountEvent>,
}

impl Account {
    /// Subscribe for changes.
    fn subscribe(&self) -> mpsc::UnboundedReceiver<AccountNotification> {
        let (tx, rx) = mpsc::unbounded();
        let msg = AccountEvent::Subscribe { tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a request.
    fn request(&self, request: AccountRequest) -> oneshot::Receiver<AccountResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = AccountEvent::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}

#[derive(Debug)]
enum WalletEvent {
    Subscribe {
        tx: mpsc::UnboundedSender<WalletNotification>,
    },
    Request {
        request: WalletRequest,
        tx: oneshot::Sender<WalletResponse>,
    },
}

struct AccountHandle {
    /// Wallet API.
    account: Account,
    /// Wallet Notifications.
    account_notifications: mpsc::UnboundedReceiver<AccountNotification>,
}

pub struct WalletService {
    accounts_dir: PathBuf,
    network_skey: pbc::SecretKey,
    network_pkey: pbc::PublicKey,
    network: Network,
    node: Node,
    executor: TaskExecutor,
    stake_epochs: u64,
    max_inputs_in_tx: usize,
    accounts: HashMap<AccountId, AccountHandle>,
    subscribers: Vec<mpsc::UnboundedSender<WalletNotification>>,
    events: mpsc::UnboundedReceiver<WalletEvent>,
}

impl WalletService {
    pub fn new(
        accounts_dir: &Path,
        network_skey: pbc::SecretKey,
        network_pkey: pbc::PublicKey,
        network: Network,
        node: Node,
        executor: TaskExecutor,
        stake_epochs: u64,
        max_inputs_in_tx: usize,
    ) -> Result<(Self, Wallet), Error> {
        let (outbox, events) = mpsc::unbounded::<WalletEvent>();
        let subscribers: Vec<mpsc::UnboundedSender<WalletNotification>> = Vec::new();
        let mut service = WalletService {
            accounts_dir: accounts_dir.to_path_buf(),
            network_skey,
            network_pkey,
            network,
            node,
            executor,
            stake_epochs,
            max_inputs_in_tx,
            accounts: HashMap::new(),
            subscribers,
            events,
        };

        info!("Scanning directory {:?} for account keys", accounts_dir);

        // Scan directory for accounts.
        for entry in fs::read_dir(accounts_dir)? {
            let entry = entry?;
            let name = entry.file_name().into_string();
            // Skip non-UTF-8 filenames
            if name.is_err() {
                continue;
            }
            if name.unwrap().starts_with(".") || !entry.file_type()?.is_dir() {
                continue;
            }

            // Find a secret key.
            let account_skey_file = entry.path().join("account.skey");
            let account_pkey_file = entry.path().join("account.pkey");
            if !account_skey_file.exists() || !account_pkey_file.exists() {
                continue;
            }

            debug!("Found a potential secret key: {:?}", account_skey_file);

            // Extract account name.
            let account_id: String = match entry.file_name().into_string() {
                Ok(id) => id,
                Err(os_string) => {
                    warn!("Invalid folder name: folder={:?}", os_string);
                    continue;
                }
            };

            debug!("Recovering account {}", account_id);
            service.open_account(&account_id)?;
            info!("Recovered account {}", account_id);
        }

        info!("Found {} account(s)", service.accounts.len());
        let api = Wallet { outbox };
        Ok((service, api))
    }

    ///
    /// Open existing account.
    ///
    fn open_account(&mut self, account_id: &str) -> Result<(), Error> {
        let account_dir = self.accounts_dir.join(account_id);
        let account_database_dir = account_dir.join("history");
        let account_skey_file = account_dir.join("account.skey");
        let account_pkey_file = account_dir.join("account.pkey");
        let (account_service, account) = AccountService::new(
            &account_database_dir,
            &account_skey_file,
            &account_pkey_file,
            self.network_skey.clone(),
            self.network_pkey.clone(),
            self.network.clone(),
            self.node.clone(),
            self.stake_epochs,
            self.max_inputs_in_tx,
        )?;
        let account_notifications = account.subscribe();
        let handle = AccountHandle {
            account,
            account_notifications,
        };
        self.accounts.insert(account_id.to_string(), handle);
        self.executor.spawn(account_service);
        Ok(())
    }

    /// Find the next available account id.
    fn find_account_id(&self) -> AccountId {
        for i in 1..std::u64::MAX {
            let account_id = i.to_string();
            let account_dir = self.accounts_dir.join(&account_id);
            if !self.accounts.contains_key(&account_id) && !account_dir.exists() {
                return account_id;
            }
        }
        unreachable!();
    }

    ///
    /// Create a new account for provided keys.
    ///
    fn create_account(
        &mut self,
        account_skey: scc::SecretKey,
        account_pkey: scc::PublicKey,
        password: &str,
    ) -> Result<AccountId, Error> {
        let account_id = self.find_account_id();
        let account_dir = self.accounts_dir.join(format!("{}", account_id));
        fs::create_dir_all(&account_dir)?;
        let account_skey_file = account_dir.join("account.skey");
        let account_pkey_file = account_dir.join("account.pkey");
        write_account_pkey(&account_pkey_file, &account_pkey)?;
        write_account_skey(&account_skey_file, &account_skey, password)?;
        self.open_account(&account_id)?;
        Ok(account_id)
    }

    fn handle_control_request(
        &mut self,
        request: WalletControlRequest,
    ) -> Result<WalletControlResponse, Error> {
        match request {
            WalletControlRequest::ListAccounts {} => {
                let accounts = self.accounts.keys().cloned().collect();
                Ok(WalletControlResponse::AccountsInfo { accounts })
            }
            WalletControlRequest::CreateAccount { password } => {
                let (account_skey, account_pkey) = scc::make_random_keys();
                let account_id = self.create_account(account_skey, account_pkey, &password)?;
                Ok(WalletControlResponse::AccountCreated { account_id })
            }
            WalletControlRequest::RecoverAccount { recovery, password } => {
                info!("Recovering keys...");
                let account_skey = recovery_to_account_skey(&recovery)?;
                let account_pkey: scc::PublicKey = account_skey.clone().into();
                info!(
                    "Recovered a account key: pkey={}",
                    String::from(&account_pkey)
                );
                let account_id = self.create_account(account_skey, account_pkey, &password)?;
                Ok(WalletControlResponse::AccountCreated { account_id })
            }
            WalletControlRequest::DeleteAccount { account_id } => {
                match self.accounts.remove(&account_id) {
                    Some(_handle) => {
                        warn!("Removing account {}", account_id);
                        let account_dir = self.accounts_dir.join(&account_id);
                        if account_dir.exists() {
                            let suffix = Timestamp::now()
                                .duration_since(Timestamp::UNIX_EPOCH)
                                .as_secs();
                            let trash_dir = self.accounts_dir.join(".trash");
                            if !trash_dir.exists() {
                                fs::create_dir_all(&trash_dir)?;
                            }
                            let account_dir_bkp =
                                trash_dir.join(format!("{}-{}", &account_id, suffix));
                            warn!("Renaming {:?} to {:?}", account_dir, account_dir_bkp);
                            fs::rename(account_dir, account_dir_bkp)?;
                        }
                        // AccountService will be destroyed automatically.
                        Ok(WalletControlResponse::AccountDeleted { account_id })
                    }
                    None => Ok(WalletControlResponse::Error {
                        error: format!("Unknown account: {}", account_id),
                    }),
                }
            }
        }
    }

    fn handle_account_request(
        &mut self,
        account_id: String,
        request: AccountRequest,
        tx: oneshot::Sender<WalletResponse>,
    ) {
        match self.accounts.get(&account_id) {
            Some(handle) => {
                let fut = handle
                    .account
                    .request(request)
                    .into_future()
                    .map_err(|_| ())
                    .map(move |response| {
                        let r = WalletResponse::AccountResponse {
                            account_id,
                            response,
                        };
                        tx.send(r).ok(); // ignore error;
                    });
                self.executor.spawn(fut);
            }
            None => {
                let r = WalletControlResponse::Error {
                    error: format!("Unknown account: {}", account_id),
                };
                let r = WalletResponse::WalletControlResponse(r);
                tx.send(r).ok(); // ignore error;
            }
        }
    }
}

impl Future for WalletService {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // Process events.
        loop {
            match self.events.poll().expect("all errors are already handled") {
                Async::Ready(Some(event)) => match event {
                    WalletEvent::Subscribe { tx } => {
                        self.subscribers.push(tx);
                    }
                    WalletEvent::Request { request, tx } => {
                        match request {
                            WalletRequest::WalletControlRequest(request) => {
                                let response = match self.handle_control_request(request) {
                                    Ok(r) => r,
                                    Err(e) => WalletControlResponse::Error {
                                        error: format!("{}", e),
                                    },
                                };
                                let response = WalletResponse::WalletControlResponse(response);
                                tx.send(response).ok(); // ignore errors.
                            }
                            WalletRequest::AccountRequest {
                                account_id,
                                request,
                            } => self.handle_account_request(account_id, request, tx),
                        }
                    }
                },
                Async::Ready(None) => unreachable!(), // never happens
                Async::NotReady => break,
            }
        }

        // Forward notifications.
        for (account_id, handle) in self.accounts.iter_mut() {
            loop {
                match handle.account_notifications.poll() {
                    Ok(Async::Ready(Some(notification))) => {
                        let notification = WalletNotification {
                            account_id: account_id.clone(),
                            notification,
                        };
                        self.subscribers
                            .retain(move |tx| tx.unbounded_send(notification.clone()).is_ok());
                    }
                    Ok(Async::Ready(None)) => panic!("AccountService has died"),
                    Ok(Async::NotReady) => break,
                    Err(()) => unreachable!(),
                }
            }
        }

        Ok(Async::NotReady)
    }
}

#[derive(Debug, Clone)]
pub struct Wallet {
    outbox: mpsc::UnboundedSender<WalletEvent>,
}

impl Wallet {
    /// Subscribe for changes.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<WalletNotification> {
        let (tx, rx) = mpsc::unbounded();
        let msg = WalletEvent::Subscribe { tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }

    /// Execute a Wallet Request.
    pub fn request(&self, request: WalletRequest) -> oneshot::Receiver<WalletResponse> {
        let (tx, rx) = oneshot::channel();
        let msg = WalletEvent::Request { request, tx };
        self.outbox.unbounded_send(msg).expect("connected");
        rx
    }
}
