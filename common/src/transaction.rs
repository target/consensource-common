use addressing;
use addressing::{CERTIFICATE, ORGANIZATION, RESERVED_SPACE, STANDARD};
use crypto::digest::Digest;
use crypto::sha2::Sha512;
use error::ConsenSourceError;
use proto::payload;
use proto::payload::CertificateRegistryPayload_Action;
use protobuf::{Message, RepeatedField};
use sawtooth_sdk::messages::transaction::{Transaction, TransactionHeader};
use sawtooth_sdk::signing::Signer;
use std::time::Instant;

/// Creates a nonce appropriate for a TransactionHeader
fn create_nonce() -> String {
    let elapsed = Instant::now().elapsed();
    format!("{}{}", elapsed.as_secs(), elapsed.subsec_nanos())
}

/// Returns a hex string representation of the supplied bytes
///
/// # Arguments
///
/// * `b` - input bytes
fn bytes_to_hex_str(b: &[u8]) -> String {
    b.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

pub trait Transact: Message {
    /// Wraps the action in a payload Protobuf type
    ///
    /// Sets the payload action enum and the associated action field
    fn make_payload(&self) -> payload::CertificateRegistryPayload;
    /// Returns a Vec of addresses this transaction needs to read from
    /// without considering the agent's org
    ///
    /// # Arguments
    ///
    /// * `public_key` - the public key of the signer to be used to sign the transaction
    fn inputs_without_org(&self, public_key: String) -> Vec<String>;
    /// Returns a Vec of addresses this transaction needs to write to
    /// without considering the agent's org
    ///
    /// # Arguments
    ///
    /// * `public_key` - the public key of the signer to be used to sign the transaction
    fn outputs_without_org(&self, public_key: String) -> Vec<String>;
    /// Returns a Transaction Result for this action type
    /// without considering the agent's org for inputs/outputs
    ///
    /// # Arguments
    ///
    /// * `signer` - the signer to be used to sign the transaction
    /// * `org_id` - the organization id of the signer's agent
    fn make_transaction_without_org(
        &self,
        signer: &Signer,
    ) -> Result<Transaction, ConsenSourceError> {
        let payload = self.make_payload();
        let mut txn = Transaction::new();
        let mut txn_header = TransactionHeader::new();

        txn_header.set_family_name(String::from(addressing::FAMILY_NAMESPACE));
        txn_header.set_family_version(String::from(addressing::FAMILY_VERSION));
        txn_header.set_nonce(create_nonce());
        txn_header.set_signer_public_key(signer.get_public_key()?.as_hex());
        txn_header.set_batcher_public_key(signer.get_public_key()?.as_hex());

        txn_header.set_inputs(RepeatedField::from_vec(
            self.inputs_without_org(signer.get_public_key()?.as_hex()),
        ));
        txn_header.set_outputs(RepeatedField::from_vec(
            self.outputs_without_org(signer.get_public_key()?.as_hex()),
        ));

        let payload_bytes = payload.write_to_bytes()?;
        let mut sha = Sha512::new();
        sha.input(&payload_bytes);
        let hash: &mut [u8] = &mut [0; 64];
        sha.result(hash);
        txn_header.set_payload_sha512(bytes_to_hex_str(hash));
        txn.set_payload(payload_bytes);

        let txn_header_bytes = txn_header.write_to_bytes()?;
        txn.set_header(txn_header_bytes.clone());

        let b: &[u8] = &txn_header_bytes;
        txn.set_header_signature(signer.sign(b)?);

        Ok(txn)
    }
    /// Returns a Vec of addresses this transaction needs to read from
    ///
    /// # Arguments
    ///
    /// * `public_key` - the public key of the signer to be used to sign the transaction
    /// * `org_id` - the organization id of the signer's agent
    fn inputs(&self, public_key: String, org_id: String) -> Vec<String> {
        let mut inputs = self.inputs_without_org(public_key);
        if let Some(org_id) = org_id.into() {
            inputs.push(addressing::make_organization_address(&org_id));
        }
        inputs
    }
    /// Returns a Vec of addresses this transaction needs to write to
    ///
    /// # Arguments
    ///
    /// * `public_key` - the public key of the signer to be used to sign the transaction
    /// * `org_id` - the organization id of the signer's agent
    fn outputs(&self, public_key: String, _org_id: String) -> Vec<String> {
        self.outputs_without_org(public_key)
    }
    /// Returns a Transaction Result for this action type
    ///
    /// # Arguments
    ///
    /// * `signer` - the signer to be used to sign the transaction
    /// * `org_id` - the organization id of the signer's agent
    fn make_transaction(
        &self,
        signer: &Signer,
        org_id: &str,
    ) -> Result<Transaction, ConsenSourceError> {
        let payload = self.make_payload();
        let mut txn = Transaction::new();
        let mut txn_header = TransactionHeader::new();

        txn_header.set_family_name(String::from(addressing::FAMILY_NAMESPACE));
        txn_header.set_family_version(String::from(addressing::FAMILY_VERSION));
        txn_header.set_nonce(create_nonce());
        txn_header.set_signer_public_key(signer.get_public_key()?.as_hex());
        txn_header.set_batcher_public_key(signer.get_public_key()?.as_hex());

        txn_header.set_inputs(RepeatedField::from_vec(
            self.inputs(signer.get_public_key()?.as_hex(), org_id.to_string()),
        ));
        txn_header.set_outputs(RepeatedField::from_vec(
            self.outputs(signer.get_public_key()?.as_hex(), org_id.to_string()),
        ));

        let payload_bytes = payload.write_to_bytes()?;
        let mut sha = Sha512::new();
        sha.input(&payload_bytes);
        let hash: &mut [u8] = &mut [0; 64];
        sha.result(hash);
        txn_header.set_payload_sha512(bytes_to_hex_str(hash));
        txn.set_payload(payload_bytes);

        let txn_header_bytes = txn_header.write_to_bytes()?;
        txn.set_header(txn_header_bytes.clone());

        let b: &[u8] = &txn_header_bytes;
        txn.set_header_signature(signer.sign(b)?);

        Ok(txn)
    }
}

impl Transact for payload::CreateAgentAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        vec![agent_address]
    }
    fn outputs_without_org(&self, public_key: String) -> Vec<String> {
        self.inputs_without_org(public_key)
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::CREATE_AGENT;
        payload.set_create_agent(self.clone());
        payload
    }
}

impl Transact for payload::CreateOrganizationAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let org_address = addressing::make_organization_address(&self.id);
        vec![agent_address, org_address]
    }
    fn outputs_without_org(&self, public_key: String) -> Vec<String> {
        self.inputs_without_org(public_key)
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::CREATE_ORGANIZATION;
        payload.set_create_organization(self.clone());
        payload
    }
}

impl Transact for payload::UpdateOrganizationAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let org_address = addressing::make_organization_address(&self.id);
        vec![agent_address, org_address]
    }
    fn outputs_without_org(&self, public_key: String) -> Vec<String> {
        self.inputs_without_org(public_key)
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::UPDATE_ORGANIZATION;
        payload.set_update_organization(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::AuthorizeAgentAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let authorizer_agent_address = addressing::make_agent_address(&public_key);
        let target_agent_address = addressing::make_agent_address(&self.public_key);
        vec![authorizer_agent_address, target_agent_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let target_agent_address = addressing::make_agent_address(&self.public_key);
        vec![target_agent_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::AUTHORIZE_AGENT;
        payload.set_authorize_agent(self.clone());
        payload
    }
    fn outputs(&self, public_key: String, org_id: String) -> Vec<String> {
        let mut outputs = self.outputs_without_org(public_key);
        if let Some(org_id) = org_id.into() {
            outputs.push(addressing::make_organization_address(&org_id));
        }
        outputs
    }
}

/// Needs to called with org_id
impl Transact for payload::IssueCertificateAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let cert_address = addressing::make_certificate_address(&self.id);
        let factory_address = addressing::make_organization_address(&self.factory_id);
        vec![agent_address, cert_address, factory_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let cert_address = addressing::make_certificate_address(&self.id);
        vec![cert_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::ISSUE_CERTIFICATE;
        payload.set_issue_certificate(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::CreateStandardAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let standard_address = addressing::make_standard_address(&self.standard_id);
        vec![agent_address, standard_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let standard_address = addressing::make_standard_address(&self.standard_id);
        vec![standard_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::CREATE_STANDARD;
        payload.set_create_standard(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::UpdateStandardAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let standard_address = addressing::make_standard_address(&self.standard_id);
        vec![agent_address, standard_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let standard_address = addressing::make_standard_address(&self.standard_id);
        vec![standard_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::UPDATE_STANDARD;
        payload.set_update_standard(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::AccreditCertifyingBodyAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let standard_address = addressing::make_standard_address(&self.standard_id);
        let certifying_body_address =
            addressing::make_organization_address(&self.certifying_body_id);
        vec![agent_address, standard_address, certifying_body_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let certifying_body_address =
            addressing::make_organization_address(&self.certifying_body_id);
        vec![certifying_body_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::ACCREDIT_CERTIFYING_BODY_ACTION;
        payload.set_accredit_certifying_body_action(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::OpenRequestAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let request_address = addressing::make_request_address(&self.id);
        let standard_address = addressing::make_standard_address(&self.standard_id);
        vec![agent_address, request_address, standard_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let request_address = addressing::make_request_address(&self.id);
        vec![request_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::OPEN_REQUEST_ACTION;
        payload.set_open_request_action(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::CreatePreCertifiedRequestAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let request_address = addressing::make_request_address(&self.id);
        let standard_address = addressing::make_standard_address(&self.standard_id);
        vec![agent_address, request_address, standard_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let request_address = addressing::make_request_address(&self.id);
        vec![request_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::CREATE_PRE_CERTIFIED_REQUEST_ACTION;
        payload.set_create_pre_certified_request_action(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::ChangeRequestStatusAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let request_address = addressing::make_request_address(&self.request_id);
        vec![agent_address, request_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let request_address = addressing::make_request_address(&self.request_id);
        vec![request_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::CHANGE_REQUEST_STATUS_ACTION;
        payload.set_change_request_status_action(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::AssertAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let assertion_address = addressing::make_assertion_address(&self.assertion_id);
        if self.has_new_factory() {
            let factory_address = addressing::make_organization_address(
                self.get_new_factory().get_factory().get_id(),
            );
            return vec![agent_address, assertion_address, factory_address];
        } else if self.has_new_certificate() {
            let factory_address =
                addressing::make_organization_address(self.get_new_certificate().get_factory_id());
            let standard_address =
                addressing::make_standard_address(self.get_new_certificate().get_standard_id());
            return vec![
                agent_address,
                assertion_address,
                factory_address,
                standard_address,
            ];
        } else if self.has_new_standard() {
            return vec![agent_address, assertion_address];
        } else {
            return vec![];
        }
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let assertion_address = addressing::make_assertion_address(&self.assertion_id);
        if self.has_new_factory() {
            let factory_address = addressing::make_organization_address(
                self.get_new_factory().get_factory().get_id(),
            );
            return vec![assertion_address, factory_address];
        } else if self.has_new_certificate() {
            let cert_address =
                addressing::make_certificate_address(self.get_new_certificate().get_id());
            return vec![assertion_address, cert_address];
        } else if self.has_new_standard() {
            let standard_address =
                addressing::make_standard_address(self.get_new_standard().get_standard_id());
            return vec![assertion_address, standard_address];
        } else {
            return vec![];
        }
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::ASSERT_ACTION;
        payload.set_assert_action(self.clone());
        payload
    }
}

impl Transact for payload::TransferAssertionAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let organization_space_prefix =
            addressing::get_family_namespace_prefix() + RESERVED_SPACE + ORGANIZATION;
        let certificate_space_prefix =
            addressing::get_family_namespace_prefix() + RESERVED_SPACE + CERTIFICATE;
        let standard_space_prefix =
            addressing::get_family_namespace_prefix() + RESERVED_SPACE + STANDARD;
        let assertion_address = addressing::make_assertion_address(&self.assertion_id);
        vec![
            agent_address,
            organization_space_prefix,
            certificate_space_prefix,
            standard_space_prefix,
            assertion_address,
        ]
    }
    fn outputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let organization_space_prefix =
            addressing::get_family_namespace_prefix() + RESERVED_SPACE + ORGANIZATION;
        let certificate_space_prefix =
            addressing::get_family_namespace_prefix() + RESERVED_SPACE + CERTIFICATE;
        let standard_space_prefix =
            addressing::get_family_namespace_prefix() + RESERVED_SPACE + STANDARD;
        let assertion_address = addressing::make_assertion_address(&self.assertion_id);
        vec![
            agent_address,
            organization_space_prefix,
            certificate_space_prefix,
            standard_space_prefix,
            assertion_address,
        ]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::TRANSFER_ASSERTION;
        payload.set_transfer_assertion_action(self.clone());
        payload
    }
}

/// Needs to called with org_id
impl Transact for payload::UpdateCertificateAction {
    fn inputs_without_org(&self, public_key: String) -> Vec<String> {
        let agent_address = addressing::make_agent_address(&public_key);
        let cert_address = addressing::make_certificate_address(&self.id);
        vec![agent_address, cert_address]
    }
    fn outputs_without_org(&self, _public_key: String) -> Vec<String> {
        let cert_address = addressing::make_certificate_address(&self.id);
        vec![cert_address]
    }
    fn make_payload(&self) -> payload::CertificateRegistryPayload {
        let mut payload = payload::CertificateRegistryPayload::new();
        payload.action = CertificateRegistryPayload_Action::UPDATE_CERTIFICATE;
        payload.set_update_certificate(self.clone());
        payload
    }
}
