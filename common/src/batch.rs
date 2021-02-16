use error::ConsenSourceError;
use protobuf::{Message, RepeatedField};
use sawtooth_sdk::messages::batch::{Batch, BatchHeader, BatchList};
use sawtooth_sdk::messages::transaction::Transaction;
use sawtooth_sdk::signing::Signer;

pub trait ToBatch {
    /// Returns a Batch for the given Transaction and Signer
    ///
    /// # Arguments
    ///
    /// * `signer` - the signer to be used to sign the transaction
    ///
    /// # Errors
    ///
    /// If an error occurs during serialization of the provided Transaction or
    /// internally created `BatchHeader`, a `ConsenSourceError::ProtobufError` is
    /// returned.
    ///
    /// If a signing error occurs, a `ConsenSourceError::SigningError` is returned.
    fn to_batch(&self, signer: &Signer) -> Result<Batch, ConsenSourceError>;
    /// Returns a BatchList containing the provided Batch
    ///
    /// # Arguments
    ///
    /// * `signer` - the signer to be used to sign the transaction
    fn to_batch_list(&self, signer: &Signer) -> Result<BatchList, ConsenSourceError> {
        let mut batch_list = BatchList::new();
        batch_list.set_batches(RepeatedField::from_vec(vec![self.to_batch(signer)?]));
        Ok(batch_list)
    }
}

impl ToBatch for Transaction {
    fn to_batch(&self, signer: &Signer) -> Result<Batch, ConsenSourceError> {
        let mut batch = Batch::new();
        let mut batch_header = BatchHeader::new();

        batch_header
            .set_transaction_ids(RepeatedField::from_vec(vec![self.header_signature.clone()]));
        batch_header.set_signer_public_key(signer.get_public_key()?.as_hex());
        batch.set_transactions(RepeatedField::from_vec(vec![self.to_owned()]));

        let batch_header_bytes = batch_header.write_to_bytes()?;
        batch.set_header(batch_header_bytes.clone());

        let b: &[u8] = &batch_header_bytes;
        batch.set_header_signature(signer.sign(b)?);

        Ok(batch)
    }
}
impl ToBatch for Vec<Transaction> {
    fn to_batch(&self, signer: &Signer) -> Result<Batch, ConsenSourceError> {
        let mut batch = Batch::new();
        let mut batch_header = BatchHeader::new();
        batch_header.set_transaction_ids(RepeatedField::from_vec(
            self.iter()
                .map(|txn| txn.header_signature.clone())
                .collect(),
        ));
        batch_header.set_signer_public_key(signer.get_public_key()?.as_hex());
        batch.set_transactions(RepeatedField::from_ref(self));

        let batch_header_bytes = batch_header.write_to_bytes()?;
        batch.set_header(batch_header_bytes.clone());

        let b: &[u8] = &batch_header_bytes;
        batch.set_header_signature(signer.sign(b)?);

        Ok(batch)
    }
}

// Unit tests
#[cfg(test)]
mod tests {
    use crate::action::create_agent;
    use crate::prelude::*;
    use sawtooth_sdk::signing;
    use sawtooth_sdk::signing::CryptoFactory;
    const AGENT_NAME: &str = "test_agent";
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn create_batch_test() {
        // Create test signer
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let ms_since_epoch = since_the_epoch.as_secs();

        let test_txn = create_agent(AGENT_NAME, ms_since_epoch)
            .make_transaction_without_org(&signer)
            .expect("Failed to create transaction");

        let test_batch = test_txn.to_batch(&signer);

        assert!(test_batch.is_ok());

        assert_eq!(
            test_batch.unwrap().get_transactions().get(0),
            Some(&test_txn)
        );
    }

    #[test]
    fn create_batch_with_transactions_test() {
        // Create test signer
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let ms_since_epoch = since_the_epoch.as_secs();

        let test_txn_1 = create_agent(AGENT_NAME, ms_since_epoch)
            .make_transaction_without_org(&signer)
            .expect("Failed to create transaction");

        let test_txn_2 = create_agent(AGENT_NAME, ms_since_epoch)
            .make_transaction_without_org(&signer)
            .expect("Failed to create transaction");

        let test_batch = vec![test_txn_1.clone(), test_txn_2.clone()].to_batch(&signer);

        assert!(test_batch.is_ok());

        let unwrapped_test_batch = test_batch.unwrap();

        assert_eq!(
            unwrapped_test_batch.get_transactions().get(0),
            Some(&test_txn_1)
        );

        assert_eq!(
            unwrapped_test_batch.get_transactions().get(1),
            Some(&test_txn_2)
        );
    }

    #[test]
    fn create_batch_list_test() {
        // Create test signer
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let ms_since_epoch = since_the_epoch.as_secs();

        let test_txn = create_agent(AGENT_NAME, ms_since_epoch)
            .make_transaction_without_org(&signer)
            .expect("Failed to create transaction");

        let batch_list = test_txn.to_batch_list(&signer);

        assert!(batch_list.is_ok());

        let unwrapped_batch_list = batch_list.unwrap();

        assert!(unwrapped_batch_list.get_batches().len() == 1);

        assert_eq!(
            unwrapped_batch_list.get_batches().get(0),
            Some(&test_txn.to_batch(&signer).unwrap())
        );
    }

    #[test]
    fn create_batch_list_with_transactions_test() {
        // Create test signer
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let ms_since_epoch = since_the_epoch.as_secs();

        let test_txn_1 = create_agent(AGENT_NAME, ms_since_epoch)
            .make_transaction_without_org(&signer)
            .expect("Failed to create transaction");

        let test_txn_2 = create_agent(AGENT_NAME, ms_since_epoch)
            .make_transaction_without_org(&signer)
            .expect("Failed to create transaction");

        let batch_list = vec![test_txn_1.clone(), test_txn_2.clone()].to_batch_list(&signer);

        assert!(batch_list.is_ok());

        let unwrapped_batch_list = batch_list.unwrap();

        assert!(unwrapped_batch_list.get_batches().len() == 1);

        assert_eq!(
            unwrapped_batch_list
                .get_batches()
                .get(0)
                .unwrap()
                .get_transactions()
                .get(0),
            Some(&test_txn_1)
        );

        assert_eq!(
            unwrapped_batch_list
                .get_batches()
                .get(0)
                .unwrap()
                .get_transactions()
                .get(1),
            Some(&test_txn_2)
        );
    }
}
