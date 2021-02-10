use crypto::digest::Digest;
use crypto::sha2::Sha256;
use proto::certificate::Certificate_CertificateData;
use proto::organization::Factory_Address;
use proto::organization::Organization_Authorization_Role;
use proto::organization::Organization_Contact;
use proto::organization::Organization_Type;
use proto::payload;
use proto::payload::AssertAction_FactoryAssertion;
use proto::payload::IssueCertificateAction_Source;
use proto::request::Request_Status;

/// Returns a payload for creating an Agent
pub fn create_agent(name: &str, timestamp: u64) -> payload::CreateAgentAction {
    let mut agent = payload::CreateAgentAction::new();
    agent.set_name(String::from(name));
    agent.set_timestamp(timestamp);
    agent
}

/// Returns a payload for to authorize an Agent
pub fn authorize_agent(
    pub_key: &str,
    role: Organization_Authorization_Role,
) -> payload::AuthorizeAgentAction {
    let mut agent = payload::AuthorizeAgentAction::new();
    agent.set_public_key(String::from(pub_key));
    agent.set_role(role);

    agent
}

#[allow(clippy::too_many_arguments)]
pub fn create_organization(
    id: &str,
    name: &str,
    org_type: Organization_Type,
    contact_name: &str,
    contact_phone_number: &str,
    contact_language_code: &str,
    street: Option<&str>,
    city: Option<&str>,
    country: Option<&str>,
) -> payload::CreateOrganizationAction {
    let mut organization = payload::CreateOrganizationAction::new();
    organization.set_name(String::from(name));
    organization.set_id(String::from(id));
    organization.set_organization_type(org_type);

    if org_type == Organization_Type::FACTORY {
        let mut factory_address = Factory_Address::new();
        factory_address.set_street_line_1(street.unwrap().to_string());
        factory_address.set_city(city.unwrap().to_string());
        factory_address.set_country(country.unwrap().to_string());
        organization.set_address(factory_address);
    }

    let mut contact = Organization_Contact::new();
    contact.set_name(String::from(contact_name));
    contact.set_phone_number(String::from(contact_phone_number));
    contact.set_language_code(String::from(contact_language_code));
    organization.set_contacts(protobuf::RepeatedField::from_vec(vec![contact]));

    organization
}

#[allow(clippy::too_many_arguments)]
pub fn update_organization(
    id: &str,
    name: Option<&str>,
    contact_name: Option<&str>,
    contact_phone_number: Option<&str>,
    contact_language_code: Option<&str>,
    street: Option<&str>,
    city: Option<&str>,
    country: Option<&str>,
) -> payload::UpdateOrganizationAction {
    let mut organization = payload::UpdateOrganizationAction::new();
    organization.set_id(String::from(id));
    if let Some(name) = name {
        organization.set_name(String::from(name));
    }

    if let (Some(contact_name), Some(contact_phone_number), Some(contact_language_code)) =
        (contact_name, contact_phone_number, contact_language_code)
    {
        let mut contact = Organization_Contact::new();
        contact.set_name(String::from(contact_name));
        contact.set_phone_number(String::from(contact_phone_number));
        contact.set_language_code(String::from(contact_language_code));
        organization.set_contacts(protobuf::RepeatedField::from_vec(vec![contact]));
    };

    if let (Some(street), Some(city), Some(country)) = (street, city, country) {
        let mut factory_address = Factory_Address::new();
        factory_address.set_street_line_1(street.to_string());
        factory_address.set_city(city.to_string());
        factory_address.set_country(country.to_string());
        organization.set_address(factory_address);
    }

    organization
}

pub fn issue_certificate(
    id: &str,
    factory_id: &str,
    request_id: Option<&str>,
    standard_id: &str,
    cert_data: Vec<Certificate_CertificateData>,
    valid_from: &str,
    valid_to: &str,
) -> payload::IssueCertificateAction {
    let mut certificate = payload::IssueCertificateAction::new();
    certificate.set_id(id.to_string());
    if let Some(request_id) = request_id {
        certificate.set_request_id(request_id.to_string());
        certificate.set_source(IssueCertificateAction_Source::FROM_REQUEST);
    } else {
        certificate.set_factory_id(factory_id.to_string());
        certificate.set_standard_id(standard_id.to_string());
        certificate.set_source(IssueCertificateAction_Source::INDEPENDENT);
    }
    certificate.set_certificate_data(::protobuf::RepeatedField::from_vec(cert_data));
    certificate.set_valid_from(valid_from.parse().unwrap());
    certificate.set_valid_to(valid_to.parse().unwrap());

    certificate
}

pub fn update_certificate(
    id: &str,
    cert_data: Vec<Certificate_CertificateData>,
    valid_from: &str,
    valid_to: &str,
) -> payload::UpdateCertificateAction {
    let mut certificate = payload::UpdateCertificateAction::new();
    certificate.set_id(id.to_string());
    certificate.set_certificate_data(::protobuf::RepeatedField::from_vec(cert_data));
    certificate.set_valid_from(valid_from.parse().unwrap());
    certificate.set_valid_to(valid_to.parse().unwrap());

    certificate
}

pub fn create_standard(
    name: &str,
    version: &str,
    description: &str,
    link: &str,
    approval_date: u64,
) -> payload::CreateStandardAction {
    let mut standard = payload::CreateStandardAction::new();

    let mut standard_id_sha = Sha256::new();
    standard_id_sha.input_str(name);
    standard.set_standard_id(standard_id_sha.result_str());
    standard.set_name(String::from(name));
    standard.set_version(String::from(version));
    standard.set_description(String::from(description));
    standard.set_link(String::from(link));
    standard.set_approval_date(approval_date);

    standard
}

pub fn update_standard(
    name: &str,
    version: &str,
    description: &str,
    link: &str,
    approval_date: u64,
) -> payload::UpdateStandardAction {
    let mut standard = payload::UpdateStandardAction::new();

    let mut standard_id_sha = Sha256::new();
    standard_id_sha.input_str(name);
    standard.set_standard_id(standard_id_sha.result_str());
    standard.set_version(String::from(version));
    standard.set_description(String::from(description));
    standard.set_link(String::from(link));
    standard.set_approval_date(approval_date);

    standard
}

pub fn create_accreditation(
    standard_id: &str,
    certifying_body_id: &str,
    valid_from: u64,
    valid_to: u64,
) -> payload::AccreditCertifyingBodyAction {
    let mut accreditation = payload::AccreditCertifyingBodyAction::new();
    accreditation.set_standard_id(String::from(standard_id));
    accreditation.set_certifying_body_id(String::from(certifying_body_id));
    accreditation.set_valid_from(valid_from);
    accreditation.set_valid_to(valid_to);

    accreditation
}

pub fn open_request(
    request_id: &str,
    standard_id: &str,
    request_date: u64,
) -> payload::OpenRequestAction {
    let mut request = payload::OpenRequestAction::new();
    request.set_id(String::from(request_id));
    request.set_standard_id(String::from(standard_id));
    request.set_request_date(request_date);

    request
}

pub fn change_request_status(
    request_id: &str,
    status: Request_Status,
) -> payload::ChangeRequestStatusAction {
    let mut request = payload::ChangeRequestStatusAction::new();
    request.set_request_id(String::from(request_id));
    request.set_status(status);

    request
}

pub fn create_factory_assertion(
    assertion_id: &str,
    create_organization_action_payload: payload::CreateOrganizationAction,
) -> payload::AssertAction {
    let mut assertion = payload::AssertAction::new();
    assertion.set_assertion_id(String::from(assertion_id));

    let mut factory_assertion = AssertAction_FactoryAssertion::new();
    factory_assertion.set_factory(create_organization_action_payload);
    assertion.set_new_factory(factory_assertion);

    assertion
}

pub fn create_standard_assertion(
    assertion_id: &str,
    create_standard_action_payload: payload::CreateStandardAction,
) -> payload::AssertAction {
    let mut assertion = payload::AssertAction::new();
    assertion.set_assertion_id(String::from(assertion_id));
    assertion.set_new_standard(create_standard_action_payload);

    assertion
}

pub fn create_certificate_assertion(
    assertion_id: &str,
    issue_certificate_action_payload: payload::IssueCertificateAction,
) -> payload::AssertAction {
    let mut assertion = payload::AssertAction::new();
    assertion.set_assertion_id(String::from(assertion_id));
    assertion.set_new_certificate(issue_certificate_action_payload);

    assertion
}

pub fn transfer_assertion(assertion_id: &str) -> payload::TransferAssertionAction {
    let mut transfer = payload::TransferAssertionAction::new();
    transfer.set_assertion_id(String::from(assertion_id));
    transfer.set_new_owner_public_key(String::from("Plz dont use dis"));

    transfer
}
