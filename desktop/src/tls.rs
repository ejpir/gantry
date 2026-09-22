//! TLS verification is identical with or without a pin: validate the chain,
//! hostname, validity interval and handshake signatures, then additionally pin
//! the leaf. Pinning happens during the handshake, before any bearer is sent.

use crate::profiles::RemoteProfile;
use anyhow::{Context, Result, ensure};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub fn configuration(profile: &RemoteProfile) -> Result<ClientConfig> {
    profile.validate()?;
    let mut roots = RootCertStore::empty();
    if profile.ca_cert.is_empty() {
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
        ensure!(
            !roots.is_empty(),
            "No system trust roots are available; configure the remote's CA with gantry remote add"
        );
    } else {
        for certificate in profile.certificates()? {
            roots
                .add(certificate)
                .context("Invalid remote CA certificate")?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    match profile.pin()? {
        None => Ok(builder.with_root_certificates(roots).with_no_client_auth()),
        Some(expected) => {
            let normal =
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider).build()?;
            Ok(builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedVerifier { normal, expected }))
                .with_no_client_auth())
        }
    }
}

#[derive(Debug)]
struct PinnedVerifier {
    normal: Arc<WebPkiServerVerifier>,
    expected: [u8; 32],
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, Error> {
        let verified =
            self.normal
                .verify_server_cert(certificate, intermediates, name, ocsp, now)?;
        let actual: [u8; 32] = Sha256::digest(certificate.as_ref()).into();
        if actual != self.expected {
            return Err(Error::General("manager TLS fingerprint mismatch".into()));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.normal
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, Error> {
        self.normal
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.normal.supported_verify_schemes()
    }
}
