//! Node - API.

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
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use stegos_blockchain::{ElectionInfo, EscrowInfo, Output, Timestamp, Transaction};
use stegos_crypto::hash::{Hash, Hashable, Hasher};
use stegos_crypto::scc;

///
/// RPC requests.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NodeRequest {
    ElectionInfo {},
    EscrowInfo {},
    PopBlock {},
    #[serde(skip)]
    AddTransaction(Transaction),
    ValidateCertificate {
        utxo: Hash,
        spender: scc::PublicKey,
        recipient: scc::PublicKey,
        rvalue: scc::Fr,
    },
    EnableRestaking {},
    DisableRestaking {},
    GetMacroBlockInfo {
        epoch: u64,
        limit: u64,
    },
}

///
/// RPC responses.
///
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NodeResponse {
    ElectionInfo(ElectionInfo),
    EscrowInfo(EscrowInfo),
    BlockPopped,
    #[serde(skip)]
    AddTransaction {
        hash: Hash,
        status: TransactionStatus,
    },
    CertificateValid {
        epoch: u64,
        block_hash: Hash,
        is_final: bool,
        timestamp: Timestamp,
        amount: i64,
    },
    RestakingEnabled,
    RestakingDisabled,
    MacroBlockInfo {
        #[serde(flatten)]
        blocks_info: Vec<NewMacroBlock>,
    },
    Error {
        error: String,
    },
}

/// Send when synchronization status has been changed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncChanged {
    pub is_synchronized: bool,
    pub epoch: u64,
    pub offset: u32,
    pub view_change: u32,
    pub last_block_hash: Hash,
    pub last_macro_block_hash: Hash,
    pub last_macro_block_timestamp: Timestamp,
    pub local_timestamp: Timestamp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewMacroBlock {
    #[serde(flatten)]
    pub block: stegos_blockchain::MacroBlock,
    #[serde(flatten)]
    pub epoch_info: stegos_blockchain::StartEpochInfo,
    #[serde(skip)]
    pub transactions: HashMap<Hash, Transaction>,
    pub statuses: HashMap<Hash, TransactionStatus>,
}

impl NewMacroBlock {
    pub fn inputs(&self) -> impl Iterator<Item = &Hash> {
        self.block.inputs.iter()
    }
    pub fn outputs(&self) -> impl Iterator<Item = &Output> {
        self.block.outputs.iter()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RollbackMicroBlock {
    #[serde(flatten)]
    pub block: stegos_blockchain::MicroBlock,
    #[serde(skip)]
    pub recovered_transaction: HashMap<Hash, Transaction>,
    pub statuses: HashMap<Hash, TransactionStatus>,
    #[serde(skip)]
    pub recovered_inputs: HashMap<Hash, Output>,
    #[serde(skip)]
    pub pruned_outputs: Vec<Hash>,
}

impl RollbackMicroBlock {
    pub fn pruned_outputs(&self) -> impl Iterator<Item = &Hash> {
        self.pruned_outputs.iter()
    }
    pub fn recovered_inputs(&self) -> impl Iterator<Item = &Output> {
        self.recovered_inputs.values()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewMicroBlock {
    #[serde(flatten)]
    pub block: stegos_blockchain::MicroBlock,
    #[serde(skip)]
    pub transactions: HashMap<Hash, Transaction>,
    pub statuses: HashMap<Hash, TransactionStatus>,
}

impl NewMicroBlock {
    pub fn inputs(&self) -> impl Iterator<Item = &Hash> {
        self.block.transactions.iter().flat_map(|tx| tx.txins())
    }
    pub fn outputs(&self) -> impl Iterator<Item = &Output> {
        self.block.transactions.iter().flat_map(|tx| tx.txouts())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum NodeNotification {
    NewMicroBlock(NewMicroBlock),
    NewMacroBlock(NewMacroBlock),
    RollbackMicroBlock(RollbackMicroBlock),
    SyncChanged(SyncChanged),
}

impl From<SyncChanged> for NodeNotification {
    fn from(sync: SyncChanged) -> NodeNotification {
        NodeNotification::SyncChanged(sync)
    }
}

impl From<NewMacroBlock> for NodeNotification {
    fn from(block: NewMacroBlock) -> NodeNotification {
        NodeNotification::NewMacroBlock(block)
    }
}

impl From<NewMicroBlock> for NodeNotification {
    fn from(block: NewMicroBlock) -> NodeNotification {
        NodeNotification::NewMicroBlock(block)
    }
}

impl From<RollbackMicroBlock> for NodeNotification {
    fn from(block: RollbackMicroBlock) -> NodeNotification {
        NodeNotification::RollbackMicroBlock(block)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "status")]
#[serde(rename_all = "snake_case")]
pub enum TransactionStatus {
    Created {},
    Accepted {},
    Rejected {
        error: String,
    },
    /// Transaction was included in microblock.
    Prepared {
        epoch: u64,
        offset: u32,
    },
    /// Transaction was reverted back to mempool.
    Rollback {
        epoch: u64,
        offset: u32,
    },
    /// Transaction was committed to macro block.
    Committed {
        epoch: u64,
    },
    /// Transaction was rejected, because other conflicted
    Conflicted {
        epoch: u64,
        offset: Option<u32>,
    },
}

impl Hashable for TransactionStatus {
    fn hash(&self, hasher: &mut Hasher) {
        match self {
            TransactionStatus::Created {} => "Created".hash(hasher),
            TransactionStatus::Accepted {} => "Accepted".hash(hasher),
            TransactionStatus::Rejected { error } => {
                "Rejected".hash(hasher);
                error.hash(hasher)
            }
            TransactionStatus::Prepared { epoch, offset } => {
                "Prepare".hash(hasher);
                epoch.hash(hasher);
                offset.hash(hasher);
            }
            TransactionStatus::Rollback { epoch, offset } => {
                "Rollback".hash(hasher);
                epoch.hash(hasher);
                offset.hash(hasher);
            }
            TransactionStatus::Committed { epoch } => {
                "Committed".hash(hasher);
                epoch.hash(hasher);
            }
            TransactionStatus::Conflicted { epoch, offset } => {
                "Conflicted".hash(hasher);

                epoch.hash(hasher);
                if let Some(offset) = offset {
                    "some".hash(hasher);
                    offset.hash(hasher);
                } else {
                    "none".hash(hasher);
                }
            }
        }
    }
}
