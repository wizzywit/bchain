extern crate blake2;

use std::collections::HashMap;
use std::time::SystemTime;
use blake2::{Blake2b, Digest};


//blockchain container
#[derive(Debug, Clone)]
pub struct Blockchain {
    pub blocks: Vec<Block>,
    pub accounts: HashMap<String, Account>,
    pending_transactions: Vec<Transaction>,
}

trait WorldState {
    fn get_user_ids(&self) -> Vec<String>;
    fn get_account_by_id(&mut self, id: &String) -> Option<&mut Account>;
    fn create_account(&mut self, id: String, account_type: AccountType) -> Result<(), &'static str>;
}

#[derive(Debug, Clone)]
pub struct Block {
    pub(crate) transactions: Vec<Transaction>,
    prev_hash: Option<String>,
    hash: Option<String>,
    nonce: u128,
}

#[derive(Debug, Clone)]
pub struct Transaction {
    nonce: u128,
    from: String,
    created_at: SystemTime,
    pub(crate) record: TransactionData,
    signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransactionData {
    CreateUserAccount(String),
    ChangeStoreValue {key: String, value: String},
    TransferTokens {to: String, amount: u128}
}

#[derive(Debug, Clone)]
pub struct Account {
    store: HashMap<String, String>,
    acc_type: AccountType,
    tokens: u128,
}

#[derive(Debug, Clone)]
pub enum AccountType {
    User,
    Contract,
    Validator {
        correctly_validated_blocks: u128,
        incorrectly_validated_blocks: u128,
        you_get_the_idea: bool
    }
}

impl Account {
    pub fn new(account_type, AccountType) -> Self {
        return Self {
            tokens: 0,
            acc_type: account_type,
            store: HashMap::new(),
        };
    }
}

impl Blockchain {
    pub fn new() -> Self {
        Self {
            blocks: Vec::new(),
            accounts: HashMap::new(),
            pending_transactions: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    pub fn append_block(&mut self, block: Block) -> Result<(), String> {
        let is_genesis = self.len() == 0;

        if !block.verify_own_hash() {
            Err("The block hash is mismatching! (Code: 93820394)".into())
        }
        
        if !(block.prev_hash == self.get_last_block_hash()) {
            Err("The new block has to point to the previous block (Code: 3948230)".into())
        }
        
        if block.get_transaction_count() == 0 {
            Err("There has to be at least one transaction inside the block! (Code: 9482930)".into())
        }

        let old_state = self.accounts.clone();
        for (i, transaction) in block.transactions.iter().enumerate() {
            if let Err(err) = transaction.execute(self, &is_genesis) {
                self.accounts = old_state;
                Err(format!("Could not execute transaction {} due to `{}`. Rolling back (Code: 38203984)", i + 1, err))
            }
        }
        Ok(())
    }

    pub fn get_last_block_hash(&self) -> Option<String> {
        if self.len() == 0 {
            None
        }
        self.blocks[self.blocks.len() - 1].hash.clone()
    }

    pub fn check_validity(&self) -> Result<(), String> {
        for (block_num, block) in self.blocks.iter().enumerate() {

            // Check if block saved hash matches to calculated hash
            if !block.verify_own_hash() {
                return Err(format!("Stored hash for Block #{} \
                    does not match calculated hash (Code: 665234234)", block_num + 1).into());
            }

            // Check previous black hash points to actual previous block
            if block_num == 0 {
                // Genesis block should point to nowhere
                if block.prev_hash.is_some() {
                    return Err("The genesis block has a previous hash set which \
                     it shouldn't Code :394823098".into());
                }
            } else {
                // Non genesis blocks should point to previous blocks hash (which is validated before)
                if block.prev_hash.is_none() {
                    return Err(format!("Block #{} has no previous hash set", block_num + 1).into());
                }

                // Store the values locally to use them within the error message on failure
                let prev_hash_proposed = block.prev_hash.as_ref().unwrap();
                let prev_hash_actual = self.blocks[block_num - 1].hash.as_ref().unwrap();

                if !(&block.prev_hash == &self.blocks[block_num - 1].hash) {
                    return Err(format!("Block #{} is not connected to previous block (Hashes do \
                    not match. Should be `{}` but is `{}`)", block_num, prev_hash_proposed,
                                       prev_hash_actual).into());
                }
            }

            // Check if transactions are signed correctly
            for (transaction_num, transaction) in block.transactions.iter().enumerate() {

                // Careful! With that implementation an unsigned message will always
                // be valid! You may remove the first check to only accept signed transactions
                if transaction.is_signed() && !transaction.check_signature() {
                    return Err(format!("Transaction #{} for Block #{} has an invalid signature \
                    (Code: 4398239048)", transaction_num + 1, block_num + 1));
                }
            }
        }
        Ok(())
    }
}

impl Block {
    pub fn new(prev_hash: Option<String>) -> Self {
        Self {
            nonce: 0,
            hash: None,
            prev_hash,
            transactions: Vec::new(),
        }
    }

    pub fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = Blake2b::new();

        for transaction in self.transactions.iter() {
            hasher.update(transaction.calculate_hash)
        }

        let block_as_string = format!("{:?}", (&self.prev_hash, &self.nonce))
        hasher.update(&block_as_string)
        Vec::from(hasher.finalize().as_ref())
    }

        /// Appends a transaction to the queue
    pub fn add_transaction(&mut self, transaction: Transaction) {
        self.transactions.push(transaction);
        self.update_hash();
    }

    /// Will return the amount of transactions
    pub fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Will update the hash field by including all transactions currently inside
    /// the public modifier is only for the demonstration of attacks
    pub(crate) fn update_hash(&mut self) {
        self.hash = Some(byte_vector_to_string(&self.calculate_hash()));
    }

    pub fn verify_own_hash(&self) -> bool {
        if self.hash.is_some() && self.hash.as_ref().unwrap().eq(
            &byte_vector_to_string(&self.calculate_hash())
        ) {
            return true;
        }
        false
    }
}

impl WorldState for Blockchain {
    fn get_user_ids(&self) -> Vec<String> {
        self.accounts.keys().map(|s| s.clone()).collect()
    }

    fn get_account_by_id_mut(&mut self, id: &String) -> Option<&mut Account> {
        self.accounts.get_mut(id)
    }

    fn get_account_by_id(&self, id: &String) -> Option<&Account> {
        self.accounts.get(id)
    }

    fn create_account(&mut self, id: String, account_type: AccountType) -> Result<(), &'static str> {
        return if !self.get_user_ids().contains(&id) {
            let acc = Account::new(account_type);
            self.accounts.insert(id, acc);
            Ok(())
        } else {
            Err("User already exists! (Code: 934823094)")
        };
    }
}


impl Transaction {
    pub fn new(from: String, transaction_data: TransactionData, nonce: u128) -> Self {
        Self {
            from,
            nonce,
            record: transaction_data,
            created_at: SystemTime::now(),
            signature: None,
        }
    }

    pub fn execute<T: WorldState>(&self, world_state: &mut T, is_initial: &bool) -> Result<(), &'static str> {
         // Check if sending user does exist (no one not on the chain can execute transactions)
        if let Some(_account) = world_state.get_account_by_id(&self.from) {
            // Do some more checkups later on...
        } else {
            if !is_initial {
                return Err("Account does not exist (Code: 93482390)");
            }
        }

        // match is like a switch (pattern matching) in C++ or Java
        // We will check for the type of transaction here and execute its logic
        return match &self.record {

            TransactionData::CreateUserAccount(account) => {
                world_state.create_account(account.into(), AccountType::User)
            }

            TransactionData::CreateTokens { receiver, amount } => {
                if !is_initial {
                    return Err("Token creation is only available on initial creation (Code: 2394233)");
                }
                // Get the receiving user (must exist)
                return if let Some(account) = world_state.get_account_by_id_mut(receiver) {
                    account.tokens += *amount;
                    Ok(())
                } else {
                    Err("Receiver Account does not exist (Code: 23482309)")
                };
            }

            TransactionData::TransferTokens { to, amount } => {
                let recv_tokens: u128;
                let sender_tokens: u128;

                if let Some(recv) = world_state.get_account_by_id_mut(to) {
                    // Be extra careful here, even in the genesis block the sender account has to exist
                    recv_tokens = recv.tokens;
                } else {
                    return Err("Receiver Account does not exist! (Code: 3242342380)");
                }

                if let Some(sender) = world_state.get_account_by_id_mut(&self.from) {
                    sender_tokens = sender.tokens;
                } else {
                    return Err("That account does not exist! (Code: 23423923)");
                }

                let balance_recv_new = recv_tokens.checked_add(*amount);
                let balance_sender_new = sender_tokens.checked_sub(*amount);

                if balance_recv_new.is_some() && balance_sender_new.is_some() {
                    world_state.get_account_by_id_mut(&self.from).unwrap().tokens = balance_sender_new.unwrap();
                    world_state.get_account_by_id_mut(to).unwrap().tokens = balance_recv_new.unwrap();
                    return Ok(());
                } else {
                    return Err("Overspent or Arithmetic error (Code: 48239084203)");
                }
            }

            _ => { // Not implemented transaction type
                Err("Unknown Transaction type (not implemented) (Code: 487289724389)")
            }
        };
    }

    /// Will calculate the hash using Blake2 hasher
    pub fn calculate_hash(&self) -> Vec<u8> {
        let mut hasher = Blake2b::new();
        let transaction_as_string = format!("{:?}", (&self.created_at, &self.record, &self.from, &self.nonce));

        hasher.update(&transaction_as_string);
        return Vec::from(hasher.finalize().as_ref());
    }

    /// Will hash the transaction and check if the signature is valid
    /// (i.e., it is created by the owners private key)
    /// if the message is not signed it will always return false
    pub fn check_signature(&self) -> bool {
        if !(self.is_signed()) {
            return false;
        }

        //@TODO check signature
        false
    }

    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}


/// Will take an array of bytes and transform it into a string by interpreting every byte
/// as an character due to RFC 1023 that's not possible
/// @Link https://github.com/rust-lang/rfcs/blob/master/text/1023-rebalancing-coherence.md
/// (trait and parameters are not within the local crate)
/*impl From<&std::vec::Vec<u8>> for std::string::String {
    fn from(item: &Vec<u8>) -> Self {
        item.iter().map(|&c| c as char).collect()
    }
}*/

/// Will take an array of bytes and transform it into a string by interpreting every byte
/// as an character
fn byte_vector_to_string(arr: &Vec<u8>) -> String {
    arr.iter().map(|&c| c as char).collect()
}