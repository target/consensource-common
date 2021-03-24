extern crate crypto;
extern crate protobuf;
extern crate sawtooth_sdk;

include!("../build/gen_source.rs");

// exported modules
pub mod action;
pub mod addressing;
pub mod batch;
pub mod error;
pub mod transaction;

pub mod prelude {
    pub use batch::ToBatch;
    pub use error::ConsenSourceError;
    pub use transaction::Transact;
}

pub use crate::prelude::*;

#[cfg(test)]
mod tests {
    use super::*;
    use action;
    use proto::organization::{Organization_Authorization_Role, Organization_Type};
    use proto::request::Request_Status;
    use sawtooth_sdk::signing;
    use sawtooth_sdk::signing::CryptoFactory;
    use std::time::{SystemTime, UNIX_EPOCH};
    const PUBLIC_KEY: &str = "02b018d38f052973b21235893c2d08b705269255d9bfb326ee63eb6c5841075882";
    const AGENT_NAME: &str = "test_agent";
    const ORG_ID_1: &str = "test_org_id_1";
    const ORG_ID_2: &str = "test_org_id_2";
    const ORG_NAME: &str = "test_org_name";
    const CONTACT_NAME: &str = "test_contact_name";
    const CONTACT_PHONE: &str = "test_contact_phone";
    const CONTACT_LANG: &str = "test_lang";
    const STREET: &str = "test_street";
    const CITY: &str = "test_city";
    const COUNTRY: &str = "test_country";
    const CERT_ID: &str = "test_cert_id";
    const REQUEST_ID: &str = "test_request_id";
    const STANDARD_ID: &str = "test_standard_id";
    const STANDARD_NAME: &str = "test_standard_name";
    const STANDARD_VERSION: &str = "test_standard_version";
    const STANDARD_DESCRIPTION: &str = "test_standard_desc";
    const STANDARD_LINK: &str = "test_standard_link";
    const ASSERTION_ID: &str = "test_assertion_id";

    #[test]
    fn create_agent_to_transaction() {
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let ms_since_epoch = since_the_epoch.as_secs();
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::create_agent(AGENT_NAME, ms_since_epoch);

        let transaction = action.make_transaction_without_org(&signer);

        assert!(transaction.is_ok())
    }

    #[test]
    fn create_org_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::create_organization(
            ORG_ID_1,
            ORG_NAME,
            Organization_Type::FACTORY,
            CONTACT_NAME,
            CONTACT_PHONE,
            CONTACT_LANG,
            Some(STREET),
            Some(CITY),
            Some(COUNTRY),
        );

        let transaction = action.make_transaction_without_org(&signer);

        assert!(transaction.is_ok())
    }

    #[test]
    fn update_org_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::update_organization(
            ORG_ID_1,
            Some(ORG_NAME),
            Some(CONTACT_NAME),
            Some(CONTACT_PHONE),
            Some(CONTACT_LANG),
            Some(STREET),
            Some(CITY),
            Some(COUNTRY),
        );

        let transaction = action.make_transaction_without_org(&signer);

        assert!(transaction.is_ok())
    }

    #[test]
    fn auth_agent_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action =
            action::authorize_agent(PUBLIC_KEY, Organization_Authorization_Role::TRANSACTOR);

        let transaction = action.make_transaction(&signer, ORG_ID_1);

        assert!(transaction.is_ok())
    }

    #[test]
    fn issue_certificate_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action =
            action::issue_certificate(CERT_ID, ORG_ID_1, None, STANDARD_ID, vec![], "1", "2");

        let transaction = action.make_transaction(&signer, ORG_ID_2);

        assert!(transaction.is_ok())
    }

    #[test]
    fn update_certificate_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::update_certificate(CERT_ID, vec![], "1", "2");

        let transaction = action.make_transaction(&signer, ORG_ID_1);

        assert!(transaction.is_ok())
    }

    #[test]
    fn create_standard_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::create_standard(
            STANDARD_NAME,
            STANDARD_VERSION,
            STANDARD_DESCRIPTION,
            STANDARD_LINK,
            1,
        );

        let transaction = action.make_transaction(&signer, ORG_ID_1);

        assert!(transaction.is_ok())
    }

    #[test]
    fn update_standard_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::update_standard(
            STANDARD_NAME,
            STANDARD_VERSION,
            STANDARD_DESCRIPTION,
            STANDARD_LINK,
            1,
        );

        let transaction = action.make_transaction(&signer, ORG_ID_1);

        assert!(transaction.is_ok())
    }

    #[test]
    fn create_accreditation_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::create_accreditation(STANDARD_ID, ORG_ID_1, 1, 2);

        let transaction = action.make_transaction(&signer, ORG_ID_2);

        assert!(transaction.is_ok())
    }

    #[test]
    fn open_request_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::open_request(REQUEST_ID, STANDARD_ID, 1);

        let transaction = action.make_transaction(&signer, ORG_ID_1);

        assert!(transaction.is_ok())
    }

    #[test]
    fn create_pre_certified_request_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::create_pre_certified_request(REQUEST_ID, STANDARD_ID, 1);

        let transaction = action.make_transaction(&signer, ORG_ID_1);

        assert!(transaction.is_ok())
    }

    #[test]
    fn change_request_status_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::change_request_status(REQUEST_ID, Request_Status::IN_PROGRESS);

        let transaction = action.make_transaction(&signer, ORG_ID_1);

        assert!(transaction.is_ok())
    }

    #[test]
    fn create_factory_assertion_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let create_org = action::create_organization(
            ORG_ID_1,
            ORG_NAME,
            Organization_Type::FACTORY,
            CONTACT_NAME,
            CONTACT_PHONE,
            CONTACT_LANG,
            Some(STREET),
            Some(CITY),
            Some(COUNTRY),
        );

        let action = action::create_factory_assertion(ASSERTION_ID, create_org);

        let transaction = action.make_transaction(&signer, ORG_ID_2);

        assert!(transaction.is_ok())
    }

    #[test]
    fn create_standard_assertion_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let create_standard = action::create_standard(
            STANDARD_NAME,
            STANDARD_VERSION,
            STANDARD_DESCRIPTION,
            STANDARD_LINK,
            1,
        );

        let action = action::create_standard_assertion(ASSERTION_ID, create_standard);

        let transaction = action.make_transaction(&signer, ORG_ID_1);

        assert!(transaction.is_ok())
    }

    #[test]
    fn create_certificate_assertion_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let create_cert =
            action::issue_certificate(CERT_ID, ORG_ID_1, None, STANDARD_ID, vec![], "1", "2");

        let action = action::create_certificate_assertion(ASSERTION_ID, create_cert);

        let transaction = action.make_transaction(&signer, ORG_ID_2);

        assert!(transaction.is_ok())
    }

    #[test]
    fn transfer_assertion_to_transaction() {
        let context =
            signing::create_context("secp256k1").expect("Failed to create secp256k1 context");
        let private_key = context
            .new_random_private_key()
            .expect("Failed to generate random private key");
        let factory = CryptoFactory::new(&*context);
        let signer = factory.new_signer(&*private_key);

        let action = action::transfer_assertion(ASSERTION_ID);

        let transaction = action.make_transaction_without_org(&signer);

        assert!(transaction.is_ok())
    }
}
