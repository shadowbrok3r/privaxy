use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectKeyIdentifier};
use openssl::x509::X509NameBuilder;
use openssl::x509::X509;

const ORGANIZATION_NAME: &str = "Privaxy";

pub fn make_ca_certificate() -> (X509, PKey<Private>) {
    let rsa = Rsa::generate(2048).unwrap();
    let key_pair = PKey::from_rsa(rsa).unwrap();

    let mut x509_name = X509NameBuilder::new().unwrap();
    x509_name.append_entry_by_text("C", "US").unwrap();
    x509_name.append_entry_by_text("ST", "CA").unwrap();
    x509_name
        .append_entry_by_text("O", ORGANIZATION_NAME)
        .unwrap();
    x509_name
        .append_entry_by_text("CN", ORGANIZATION_NAME)
        .unwrap();
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder().unwrap();
    cert_builder.set_version(2).unwrap();

    let serial_number = {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    };

    cert_builder.set_serial_number(&serial_number).unwrap();
    cert_builder.set_subject_name(&x509_name).unwrap();
    cert_builder.set_issuer_name(&x509_name).unwrap();
    cert_builder.set_pubkey(&key_pair).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();

    let not_after = Asn1Time::days_from_now(3650).unwrap();

    cert_builder.set_not_after(&not_after).unwrap();
    cert_builder
        .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    cert_builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();

    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&cert_builder.x509v3_context(None, None))
        .unwrap();

    cert_builder
        .append_extension(subject_key_identifier)
        .unwrap();
    cert_builder
        .sign(&key_pair, MessageDigest::sha256())
        .unwrap();

    let cert = cert_builder.build();

    (cert, key_pair)
}

/// SHA-256 of the certificate's public key info, base64, as Chromium's `--ignore-certificate-errors-spki-list` takes it.
pub fn spki_sha256(certificate: &X509) -> Result<String, openssl::error::ErrorStack> {
    use base64::Engine as _;
    let spki = certificate.public_key()?.public_key_to_der()?;
    Ok(base64::engine::general_purpose::STANDARD.encode(openssl::sha::sha256(&spki)))
}

#[cfg(test)]
mod spki_tests {
    use super::*;

    const FIXTURE: &str = "-----BEGIN CERTIFICATE-----
MIIBgzCCASmgAwIBAgIUOHDygtBsFf1oa7xumeX0Y5EcC3gwCgYIKoZIzj0EAwIw
FzEVMBMGA1UEAwwMU1BLSSBmaXh0dXJlMB4XDTI2MTAyNjE2MjMyNVoXDTM2MTAy
MzE2MjMyNVowFzEVMBMGA1UEAwwMU1BLSSBmaXh0dXJlMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEgYt1ZYh+2rHkulUzGkiKG5lj4BuOtzOVCyAlNP7ypmUKSw+w
aYxCC4XxHbxY9s9klKCIdtXEhQMoGFeiTbD6YqNTMFEwHQYDVR0OBBYEFIFr8IOm
/j/lYXPm77Jmg4BJqe+1MB8GA1UdIwQYMBaAFIFr8IOm/j/lYXPm77Jmg4BJqe+1
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgS+A2Ld2CGHDUauHT
59TVuVkV9kyrJup3SM/uzeQeuJICIQD1bmYCvjwFjH3zq3he6VBrVqnN7qL7j7v3
rQSOZeoFeg==
-----END CERTIFICATE-----";

    #[test]
    fn spki_hash_matches_openssl() {
        // openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64
        let certificate = X509::from_pem(FIXTURE.as_bytes()).unwrap();
        assert_eq!(
            spki_sha256(&certificate).unwrap(),
            "IGwMb2PY+pKxdRMO9LWDH0qYyCHdfDKUIEb/3v5mlz4="
        );
    }
}
