//! Wallet - Transactions.

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

use crate::change::*;
use crate::error::*;
use crate::snowball::ProposedUTXO;
use crate::snowball::{FEE_PER_TXOUT, MAX_SHARING_TXOUTS};
use crate::storage::{OutputValue, PaymentValue, StakeValue};
use failure::Error;
use log::*;
use serde_derive::Serialize;
use std::convert::From;
use stegos_blockchain::*;
use stegos_crypto::hash::Hash;
use stegos_crypto::pbc;
use stegos_crypto::scc::Fr;
use stegos_crypto::scc::PublicKey;
use stegos_crypto::scc::SecretKey;

/// Create trasnaction.
#[derive(Serialize, Debug, PartialEq, Eq, Clone)]
pub enum TransactionType {
    /// Transaction with cloacked UTXO, and optional comment.
    Regular(PaymentPayloadData),
    /// Transaction with uncloacked UTXO
    Public,
}

impl From<PaymentPayloadData> for TransactionType {
    fn from(data: PaymentPayloadData) -> Self {
        TransactionType::Regular(data)
    }
}

/// Create a new snowball payment transaction.
pub(crate) fn create_snowball_transaction<'a, UnspentIter>(
    sender_pkey: &PublicKey,
    recipient: &PublicKey,
    unspent_iter: UnspentIter,
    amount: i64,
    payment_fee: i64,
    data: PaymentPayloadData,
    locked_timestamp: Option<Timestamp>,
    last_block_time: Timestamp,
    max_inputs_in_tx: usize,
) -> Result<(Vec<(Hash, PaymentOutput)>, Vec<ProposedUTXO>, i64), Error>
where
    UnspentIter: Iterator<Item = (&'a PaymentOutput, i64, Option<Timestamp>)>,
{
    assert!(payment_fee == (MAX_SHARING_TXOUTS as i64) * FEE_PER_TXOUT);
    if amount < 0 {
        return Err(WalletError::NegativeAmount(amount).into());
    }

    data.validate()?;

    debug!(
        "Creating Snowball payment transaction: recipient={}, amount={}, data={:?}",
        recipient, amount, data
    );

    //
    // Find inputs
    //

    trace!("Checking for available funds in the account...");
    let fee = payment_fee;
    // let fee_change = fee + payment_fee;
    let (inputs, fee, change) = find_utxo(
        unspent_iter,
        amount,
        fee,
        fee, // fee_change,
        last_block_time,
        max_inputs_in_tx,
    )?;
    let inputs: Vec<Output> = inputs
        .into_iter()
        .map(|o| Output::PaymentOutput(o.clone()))
        .collect();
    assert!(!inputs.is_empty());

    debug!(
        "Transaction preview: recipient={}, amount={}, withdrawn={}, change={}, fee={}",
        recipient,
        amount,
        amount + change + fee,
        change,
        fee
    );
    let mut inputs_pairs = Vec::<(Hash, PaymentOutput)>::new();
    for input in &inputs {
        let h = Hash::digest(input);
        match input {
            Output::PaymentOutput(o) => {
                inputs_pairs.push((h.clone(), o.clone()));
            }
            _ => {
                return Err(WalletError::IncorrectTXINType.into());
            }
        }
        debug!("Use UTXO: hash={}", h);
    }

    //
    // Create outputs
    //

    let mut outputs: Vec<ProposedUTXO> = Vec::<ProposedUTXO>::with_capacity(2);

    // Create an output for payment
    trace!("Creating payment UTXO...");
    let output1 = ProposedUTXO {
        recip: recipient.clone(),
        amount,
        data: data.clone(),
        locked_timestamp,
        is_change: false,
    };
    outputs.push(output1);

    info!(
        "Created payment UTXO: recipient={}, amount={}, locked={:?}, data={:?}",
        recipient, amount, locked_timestamp, data
    );

    if change > 0 {
        // Create an output for change
        trace!("Creating change UTXO...");
        let data = PaymentPayloadData::Comment("Change".to_string());
        let output2 = ProposedUTXO {
            recip: sender_pkey.clone(),
            amount: change,
            data: data.clone(),
            locked_timestamp: None,
            is_change: true,
        };
        info!(
            "Created change UTXO: recipient={}, change={}, data={:?}",
            sender_pkey, change, data
        );
        outputs.push(output2);
    }

    info!(
        "Created payment transaction: recipient={}, amount={}, withdrawn={}, change={}, fee={}",
        recipient,
        amount,
        amount + change + fee,
        change,
        fee
    );

    Ok((inputs_pairs, outputs, fee))
}

/// Create a new payment transaction.
pub(crate) fn create_payment_transaction<'a, UnspentIter>(
    certificate_skey: Option<&SecretKey>,
    sender_pkey: &PublicKey,
    recipient: &PublicKey,
    unspent_iter: UnspentIter,
    amount: i64,
    payment_fee: i64,
    transaction: TransactionType,
    locked_timestamp: Option<Timestamp>,
    last_block_time: Timestamp,
    max_inputs_in_tx: usize,
) -> Result<(Vec<Output>, Vec<Output>, Fr, Vec<OutputValue>, i64), Error>
where
    UnspentIter: Iterator<Item = (&'a PaymentOutput, i64, Option<Timestamp>)>,
{
    if amount < 0 {
        return Err(WalletError::NegativeAmount(amount).into());
    }

    debug!(
        "Creating a payment transaction: recipient={:?}, amount={}",
        recipient, amount
    );

    //
    // Find inputs
    //

    trace!("Checking for available funds in the account...");
    let fee = payment_fee;
    let fee_change = fee + payment_fee;
    let (inputs, fee, change) = find_utxo(
        unspent_iter,
        amount,
        fee,
        fee_change,
        last_block_time,
        max_inputs_in_tx,
    )?;
    let inputs: Vec<Output> = inputs
        .into_iter()
        .map(|o| Output::PaymentOutput(o.clone()))
        .collect();
    assert!(!inputs.is_empty());

    debug!(
        "Transaction preview: recipient={:?}, amount={}, withdrawn={}, change={}, fee={}",
        recipient,
        amount,
        amount + change + fee,
        change,
        fee
    );
    for input in &inputs {
        debug!("Use UTXO: hash={}", Hash::digest(input));
    }

    //
    // Create outputs
    //

    let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(2);
    let mut extended_outputs = Vec::with_capacity(2);

    // Create an output for payment
    let (output1, gamma1, extended_output) = match transaction {
        TransactionType::Regular(data) => {
            data.validate()?;
            trace!("Creating payment UTXO...");
            let (output1, gamma1, rvalue) = PaymentOutput::with_payload(
                certificate_skey,
                recipient,
                amount,
                data.clone(),
                locked_timestamp,
            )?;

            // return rvalue only if signature was created.
            let rvalue = certificate_skey.map(|_| rvalue);

            let output1_hash = Hash::digest(&output1);
            info!(
                "Created payment UTXO: hash={}, recipient={}, amount={}, data={:?}, locked={:?}",
                output1_hash, recipient, amount, data, locked_timestamp
            );

            let extended_output = PaymentValue {
                output: output1.clone(),
                rvalue,
                recipient: *recipient,
                amount,
                data: data.into(),
                is_change: false,
            };

            (output1.into(), gamma1, extended_output.into())
        }
        TransactionType::Public => {
            trace!("Creating public payment UTXO...");
            let gamma1 = Fr::zero();
            let output1 = if let Some(locked_timestamp) = locked_timestamp {
                PublicPaymentOutput::new_locked(recipient, amount, locked_timestamp)
            } else {
                PublicPaymentOutput::new(recipient, amount)
            };
            let output1_hash = Hash::digest(&output1);
            info!(
                "Created public payment UTXO: hash={}, recipient={}, amount={}, locked={:?}",
                output1_hash, recipient, amount, locked_timestamp
            );

            (output1.clone().into(), gamma1, output1.into())
        }
    };

    outputs.push(output1);
    extended_outputs.push(extended_output);

    let mut gamma = gamma1;

    if change > 0 {
        // Create an output for change
        trace!("Creating change UTXO...");
        let data = PaymentPayloadData::Comment("Change".to_string());
        let (output2, gamma2, _rvalue) =
            PaymentOutput::with_payload(None, sender_pkey, change, data.clone(), None)?;
        info!(
            "Created change UTXO: hash={}, recipient={}, change={}, data={:?}",
            Hash::digest(&output2),
            sender_pkey,
            change,
            data
        );
        let extended_output = PaymentValue {
            output: output2.clone(),
            rvalue: None,
            recipient: *sender_pkey,
            amount: change,
            data: data.into(),
            is_change: true,
        };
        extended_outputs.push(extended_output.into());
        outputs.push(output2.into());
        gamma += gamma2;
    }

    info!(
        "Created payment transaction: recipient={}, amount={}, withdrawn={}, change={}, fee={}",
        recipient,
        amount,
        amount + change + fee,
        change,
        fee
    );

    assert_eq!(extended_outputs.len(), outputs.len());
    Ok((inputs, outputs, gamma, extended_outputs, fee))
}

/// Create a new staking transaction.
pub(crate) fn create_staking_transaction<'a, UnspentIter>(
    sender_skey: &SecretKey,
    sender_pkey: &PublicKey,
    validator_pkey: &pbc::PublicKey,
    validator_skey: &pbc::SecretKey,
    unspent_iter: UnspentIter,
    amount: i64,
    payment_fee: i64,
    stake_fee: i64,
    last_block_time: Timestamp,
    max_inputs_in_tx: usize,
) -> Result<(PaymentTransaction, Vec<OutputValue>), Error>
where
    UnspentIter: Iterator<Item = (&'a PaymentOutput, i64)>,
{
    if amount < 0 {
        return Err(WalletError::NegativeAmount(amount).into());
    } else if amount <= payment_fee {
        // Stake must be > PAYMENT_FEE.
        return Err(WalletError::InsufficientStake(payment_fee + 1, amount).into());
    }

    debug!(
        "Creating a staking transaction: validator={:?}, amount={}",
        validator_pkey, amount
    );

    //
    // Find inputs
    //

    trace!("Checking for available funds in the account...");
    let fee = stake_fee;
    let fee_change = fee + payment_fee;
    let unspent_iter = unspent_iter.map(|(o, a)| (o, a, None));
    let (inputs, fee, change) = find_utxo(
        unspent_iter,
        amount,
        fee,
        fee_change,
        last_block_time,
        max_inputs_in_tx,
    )?;
    let inputs: Vec<Output> = inputs
        .into_iter()
        .map(|o| Output::PaymentOutput(o.clone()))
        .collect();
    assert!(!inputs.is_empty());

    debug!(
        "Transaction preview: recipient={:?}, validator={:?}, stake={}, withdrawn={}, change={}, fee={}",
        sender_pkey,
        validator_pkey,
        amount,
        amount + change + fee,
        change,
        fee
    );
    for input in &inputs {
        debug!("Use UTXO: hash={}", Hash::digest(input));
    }

    //
    // Create outputs
    //

    let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(2);
    let mut extended_outputs = Vec::with_capacity(2);

    // Create an output for staking.
    trace!("Creating stake UTXO...");
    let output1 = StakeOutput::new(sender_pkey, validator_skey, validator_pkey, amount)?;
    info!(
        "Created stake UTXO: hash={}, recipient={}, validator={}, amount={}",
        Hash::digest(&output1),
        sender_pkey,
        validator_pkey,
        amount
    );
    let extended_output = StakeValue {
        output: output1.clone(),
        active_until_epoch: None,
    };
    outputs.push(output1.into());
    extended_outputs.push(extended_output.into());
    let mut gamma = Fr::zero();

    if change > 0 {
        // Create an output for change
        trace!("Creating change UTXO...");
        let data = PaymentPayloadData::Comment(String::from("Change for stake."));
        let (output2, gamma2, _rvalue) =
            PaymentOutput::with_payload(None, sender_pkey, change, data.clone(), None)?;
        info!(
            "Created change UTXO: hash={}, recipient={}, change={}",
            Hash::digest(&output2),
            sender_pkey,
            change
        );
        let extended_output = PaymentValue {
            output: output2.clone(),
            data,
            rvalue: None,
            recipient: *sender_pkey,
            amount: change,
            is_change: true,
        };

        extended_outputs.push(extended_output.into());
        outputs.push(output2.into());
        gamma += gamma2;
    }

    trace!("Signing transaction...");
    let tx = PaymentTransaction::new(sender_skey, &inputs, &outputs, &gamma, fee)?;
    let tx_hash = Hash::digest(&tx);
    info!(
        "Signed stake transaction: hash={}, validator={}, stake={}, withdrawn={}, change={}, fee={}",
        tx_hash,
        validator_pkey,
        amount,
        amount + change + fee,
        change,
        fee
    );

    Ok((tx, extended_outputs))
}

/// Create a new unstaking transaction.
/// NOTE: amount must include PAYMENT_FEE.
pub(crate) fn create_unstaking_transaction<'a, UnspentIter>(
    sender_skey: &SecretKey,
    sender_pkey: &PublicKey,
    validator_pkey: &pbc::PublicKey,
    validator_skey: &pbc::SecretKey,
    unspent_iter: UnspentIter,
    amount: i64,
    payment_fee: i64,
    stake_fee: i64,
    last_block_time: Timestamp,
    max_inputs_in_tx: usize,
) -> Result<(PaymentTransaction, Vec<OutputValue>), Error>
where
    UnspentIter: Iterator<Item = &'a StakeOutput>,
{
    if amount <= payment_fee {
        return Err(WalletError::NegativeAmount(amount - payment_fee).into());
    }

    debug!(
        "Creating a unstaking transaction: recipient={:?}, validator={:?}, amount={}",
        sender_pkey, validator_pkey, amount
    );

    //
    // Find inputs
    //

    trace!("Checking for staked money in the account...");
    let unspent_iter = unspent_iter.map(|o| (o, o.amount, None));
    let amount = amount - payment_fee;
    let (inputs, fee, change) = find_utxo(
        unspent_iter,
        amount,
        payment_fee,
        payment_fee + stake_fee,
        last_block_time,
        max_inputs_in_tx,
    )?;
    let inputs: Vec<Output> = inputs
        .into_iter()
        .map(|o| Output::StakeOutput(o.clone()))
        .collect();
    if fee > payment_fee && change <= payment_fee {
        // Stake must be > PAYMENT_FEE.
        return Err(WalletError::InsufficientStake(payment_fee + 1, change).into());
    }

    debug!(
        "Transaction preview: recipient={:?}, validator={:?}, unstake={}, stake={}, fee={}",
        sender_pkey, validator_pkey, amount, change, fee
    );
    for input in &inputs {
        debug!("Use stake UTXO: hash={:?}", Hash::digest(input));
    }

    //
    // Create outputs
    //

    let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(2);
    let mut extended_outputs = Vec::with_capacity(2);

    // Create an output for payment
    trace!("Creating payment UTXO...");
    let data = PaymentPayloadData::Comment(String::from("Change for stake."));
    let (output1, gamma1, _rvalue) =
        PaymentOutput::with_payload(None, sender_pkey, amount, data.clone(), None)?;
    info!(
        "Created payment UTXO: hash={}, recipient={}, amount={}",
        Hash::digest(&output1),
        sender_pkey,
        amount
    );
    let extended_output = PaymentValue {
        output: output1.clone(),
        data,
        rvalue: None,
        recipient: *sender_pkey,
        amount: change,
        is_change: false,
    };

    extended_outputs.push(extended_output.into());
    outputs.push(output1.into());

    let gamma = gamma1;

    if change > 0 {
        // Create an output for staking.
        assert_eq!(fee, payment_fee + stake_fee);
        trace!("Creating stake UTXO...");
        let output2 = StakeOutput::new(sender_pkey, validator_skey, validator_pkey, change)?;
        info!(
            "Created stake UTXO: hash={}, validator={}, amount={}",
            Hash::digest(&output2),
            validator_pkey,
            change
        );
        let extended_output = StakeValue {
            output: output2.clone(),
            active_until_epoch: None,
        };
        extended_outputs.push(extended_output.into());
        outputs.push(output2.into());
    }

    trace!("Signing transaction...");
    let tx = PaymentTransaction::new(&sender_skey, &inputs, &outputs, &gamma, fee)?;
    let tx_hash = Hash::digest(&tx);
    info!(
        "Signed unstake transaction: hash={}, validator={}, unstake={}, stake={}, fee={}",
        tx_hash, validator_pkey, amount, change, fee
    );

    Ok((tx, extended_outputs))
}

/// Create a restaking transaction.
pub(crate) fn create_restaking_transaction<'a, UnspentIter>(
    _sender_skey: &SecretKey,
    sender_pkey: &PublicKey,
    validator_pkey: &pbc::PublicKey,
    validator_skey: &pbc::SecretKey,
    stakes_iter: UnspentIter,
) -> Result<(RestakeTransaction, Vec<OutputValue>), Error>
where
    UnspentIter: Iterator<Item = &'a StakeOutput>,
{
    debug!(
        "Creating a restaking transaction: recipient={}, new_validator_key={}",
        sender_pkey, validator_pkey
    );

    let mut inputs: Vec<Output> = Vec::new();
    let mut outputs: Vec<Output> = Vec::new();
    let mut extended_outputs = Vec::with_capacity(2);
    for input in stakes_iter {
        debug!(
            "Unstake: hash={}, validator={}, amount={}",
            Hash::digest(&input),
            validator_pkey,
            input.amount
        );
        inputs.push(Output::StakeOutput(input.clone()));

        trace!("Creating StakeUTXO...");
        let output = StakeOutput::new(sender_pkey, validator_skey, validator_pkey, input.amount)?;
        debug!(
            "Stake: hash={}, validator={}, amount={}",
            Hash::digest(&output),
            validator_pkey,
            input.amount
        );
        let extended_output = StakeValue {
            output: output.clone(),
            active_until_epoch: None,
        };
        extended_outputs.push(extended_output.into());
        outputs.push(output.into());
    }

    trace!("Signing transaction...");
    let tx = RestakeTransaction::new(validator_skey, validator_pkey, &inputs, &outputs)?;
    let tx_hash = Hash::digest(&tx);
    info!(
        "Created a restaking transaction: hash={}, inputs={}, outputs={}",
        tx_hash,
        tx.txins.len(),
        tx.txouts.len()
    );

    Ok((tx, extended_outputs))
}

/// Create a cloaking transaction.
pub(crate) fn create_cloaking_transaction<'a, UnspentIter>(
    sender_skey: &SecretKey,
    recipient: &PublicKey,
    unspent_iter: UnspentIter,
    payment_fee: i64,
    last_block_time: Timestamp,
) -> Result<(PaymentTransaction, OutputValue), Error>
where
    UnspentIter: Iterator<Item = &'a PublicPaymentOutput>,
{
    assert!(payment_fee == (MAX_SHARING_TXOUTS as i64) * FEE_PER_TXOUT);

    let data = PaymentPayloadData::Comment(String::from("Exchange public UTXOs to cloaked"));

    debug!("Creating a cloaking transaction: recipient={:?}", recipient);

    //
    // Find inputs
    //

    trace!("Checking for available public funds in the account...");
    let fee = payment_fee;
    let mut inputs = Vec::new();
    let mut total_amount = -payment_fee;

    for input in unspent_iter {
        if let Some(time) = input.locked_timestamp {
            if time >= last_block_time {
                trace!(
                    "Ignoring output because its locked, locked_time={:?}, \
                     macro_block_time={:?}, output={:?}",
                    time,
                    last_block_time,
                    input
                );
                continue;
            }
        }
        debug!("Use UTXO: hash={}", Hash::digest(input));
        let PublicPaymentOutput { amount, .. } = input;
        inputs.push(Output::PublicPaymentOutput(input.clone()));
        total_amount += amount;
    }

    debug!(
        "Transaction preview: recipient={:?}, amount={}, withdrawn={}, fee={}",
        recipient,
        total_amount,
        total_amount + fee,
        fee
    );

    if total_amount <= 0 {
        return Err(WalletError::NegativeAmount(total_amount).into());
    }

    assert!(!inputs.is_empty());

    //
    // Create outputs
    //

    let mut outputs: Vec<Output> = Vec::<Output>::with_capacity(1);
    // Create an output for payment

    data.validate()?;
    trace!("Creating payment UTXO...");

    let (output, gamma, _rvalue) =
        PaymentOutput::with_payload(None, recipient, total_amount, data.clone(), None)?;
    let output1_hash = Hash::digest(&output);
    info!(
        "Created payment UTXO: hash={}, recipient={}, amount={}, data={:?}",
        output1_hash, recipient, total_amount, data
    );

    let extended_output = PaymentValue {
        amount: total_amount,
        rvalue: None,
        recipient: *recipient,
        data,
        output: output.clone(),
        is_change: false,
    };

    outputs.push(output.into());
    info!(
        "Created payment transaction: recipient={}, amount={}, withdrawn={}, fee={}",
        recipient,
        total_amount,
        total_amount + fee,
        fee
    );
    Ok((
        PaymentTransaction::new(sender_skey, &inputs, &outputs, &gamma, fee)?,
        extended_output.into(),
    ))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use stegos_crypto::pbc;
    use stegos_crypto::scc::make_random_keys;

    /// Check transaction signing and validation.
    #[test]
    fn unstaking_transactions() {
        let payment_fee: i64 = 1;
        let stake_fee: i64 = 1;
        let max_inputs_in_tx: usize = 3;
        assert!(payment_fee > 0 && stake_fee > 0);
        simple_logger::init_with_level(log::Level::Debug).unwrap_or_default();

        let (skey, pkey) = make_random_keys();
        let (validator_skey, validator_pkey) = pbc::make_random_keys();

        let stake: i64 = 100;

        // Stake money.
        let output = StakeOutput::new(&pkey, &validator_skey, &validator_pkey, stake)
            .expect("keys are valid");
        let inputs = [Output::StakeOutput(output.clone())];
        let unspent: Vec<StakeOutput> = vec![output];

        // Unstake all of the money.
        let (tx, _) = create_unstaking_transaction(
            &skey,
            &pkey,
            &validator_pkey,
            &validator_skey,
            unspent.iter(),
            stake,
            payment_fee,
            stake_fee,
            Timestamp::now(),
            max_inputs_in_tx,
        )
        .expect("tx is created");
        tx.validate(&inputs).expect("tx is valid");
        assert_eq!(tx.fee, payment_fee);
        assert_eq!(tx.txouts.len(), 1);
        match &tx.txouts.first().unwrap() {
            Output::PaymentOutput(o) => {
                let PaymentPayload { amount, .. } = o.decrypt_payload(&skey).expect("key is valid");
                assert_eq!(amount, stake - payment_fee);
            }
            _ => panic!("invalid tx"),
        }

        // Unstake part of the money.
        let unstake = stake / 2;
        let (tx, _) = create_unstaking_transaction(
            &skey,
            &pkey,
            &validator_pkey,
            &validator_skey,
            unspent.iter(),
            unstake,
            payment_fee,
            stake_fee,
            Timestamp::now(),
            max_inputs_in_tx,
        )
        .expect("tx is created");
        tx.validate(&inputs).expect("tx is valid");
        assert_eq!(tx.fee, payment_fee + stake_fee);
        assert_eq!(tx.txouts.len(), 2);
        match &tx.txouts[0] {
            Output::PaymentOutput(o) => {
                let PaymentPayload { amount, .. } = o.decrypt_payload(&skey).expect("key is valid");
                assert_eq!(amount, unstake - payment_fee);
            }
            _ => panic!("invalid tx"),
        }
        match &tx.txouts[1] {
            Output::StakeOutput(o) => {
                assert_eq!(o.amount, stake - unstake - stake_fee);
            }
            _ => panic!("invalid tx"),
        }

        // Try to unstake less than PAYMENT_FEE.
        let e = create_unstaking_transaction(
            &skey,
            &pkey,
            &validator_pkey,
            &validator_skey,
            unspent.iter(),
            payment_fee - 1,
            payment_fee,
            stake_fee,
            Timestamp::now(),
            max_inputs_in_tx,
        )
        .unwrap_err();
        match e.downcast::<WalletError>().unwrap() {
            WalletError::NegativeAmount(_amount) => {}
            _ => panic!(),
        }

        // Try to unstake PAYMENT_FEE.
        let e = create_unstaking_transaction(
            &skey,
            &pkey,
            &validator_pkey,
            &validator_skey,
            unspent.iter(),
            payment_fee,
            payment_fee,
            stake_fee,
            Timestamp::now(),
            max_inputs_in_tx,
        )
        .unwrap_err();
        match e.downcast::<WalletError>().unwrap() {
            WalletError::NegativeAmount(_amount) => {}
            _ => panic!(),
        }

        // Try to re-stake zero.
        let unstake = stake - stake_fee;
        let e = create_unstaking_transaction(
            &skey,
            &pkey,
            &validator_pkey,
            &validator_skey,
            unspent.iter(),
            unstake,
            payment_fee,
            stake_fee,
            Timestamp::now(),
            max_inputs_in_tx,
        )
        .unwrap_err();
        match e.downcast::<WalletError>().unwrap() {
            WalletError::InsufficientStake(min, got) => {
                assert_eq!(min, payment_fee + 1);
                assert_eq!(got, 0);
            }
            _ => panic!(),
        }

        // Try to re-stake PAYMENT_FEE.
        let unstake = stake - payment_fee - stake_fee;
        let e = create_unstaking_transaction(
            &skey,
            &pkey,
            &validator_pkey,
            &validator_skey,
            unspent.iter(),
            unstake,
            payment_fee,
            stake_fee,
            Timestamp::now(),
            max_inputs_in_tx,
        )
        .unwrap_err();
        match e.downcast::<WalletError>().unwrap() {
            WalletError::InsufficientStake(min, got) => {
                assert_eq!(min, payment_fee + 1);
                assert_eq!(got, payment_fee);
            }
            _ => panic!(),
        }
    }
}
