# `tokio-tls-upgrade` - Upgrade a TCP stream to TLS stream.

[![crates.io](https://img.shields.io/crates/v/tokio-tls-upgrade.svg)](https://crates.io/crates/tokio-tls-upgrade)
[![Documentation](https://docs.rs/tokio-tls-upgrade/badge.svg)](https://docs.rs/tokio-tls-upgrade)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A library for upgrading a `tokio::net::TcpStream` to a `tokio_rustls::Server::TlsStream`.

Whilst working on a custom implementation of an SMTP email server, I found that to be able to support STARTTLS, I needed to be able to upgrade a `tokio::net::TcpStream` to a `tokio_rustls::Server::TlsStream`. This was a very cumbersome process, that required a lot of research, trial and error. Mostly due to lack of documentation and examples. Therefore, I decided to create this library to make it easier for others to do the same.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
tokio-tls-upgrade = "0.1.0"
```

## Example

**Note**:
In the example below I use `rcgen` to generate a self-signed certificate for testing purposes. In a production environment, you should use a valid certificate from a trusted Certificate Authority (CA).

When using a certificate issued by a trusted CA, all you need to do is provide the paths to the certificate and key files to the `upgrade_tcp_stream` function. As well as the `TcpStream` that you want to upgrade.

If you have any questions or need help, feel free to open an issue.

```rust
use rcgen::{CertificateParams, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{Error as TlsError,ClientConfig,DigitallySignedStruct, SignatureScheme};
use rustls_pemfile::certs;
use tokio::sync::oneshot::{channel,Sender};
use std::fs::{remove_file, File};
use std::io::{Write,BufReader};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{self,AsyncReadExt,AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_tls_upgrade::upgrade_tcp_stream;

// Start a TLS server that listens on the given address and port
async fn start_tls_server(
    certificate_path: PathBuf,
    key_path: PathBuf,
    addr: &str,
    tx:Sender<u8>
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;

    tx.send(1).unwrap(); // Notify the client that the server is ready

    // Accept a new connection. Code will not proceed until a connection is made
    let (stream, _) = listener.accept().await?;

    // Upgrade the connection to a TLS connection using the library function
    let mut tls_stream = upgrade_tcp_stream(stream, certificate_path, key_path).await?;

    // Handle the stream: for example, read a message and respond
    let mut buffer = [0u8; 1024]; // Example buffer
    let n = tls_stream.read(&mut buffer).await?;
    if n > 0 {
        log::info!("Received from client: {:?}", String::from_utf8_lossy(&buffer[..n]));
        let response = b"Hello TLS client!";
        tls_stream.write_all(response).await?;
    }

    Ok(())
}

// Implement a ServerCertVerifier that does not verify the server certificate for testing purposes
#[derive(Debug)]
struct NoVerification;

/**
 * Always return ServerCertVerified::assertion() to indicate that the server certificate is verified.
 * We do this because in a test environment, where we use a self-signed certificate, we do not need to verify the server certificate.
 * However, in a production environment, you should **always** verify the server certificate to ensure that the server is who it claims to be.
 * 
 * Therefore, do NOT use this certificate verifier in production code.
 */
impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer,
        _intermediates: &[CertificateDer],
        _server_name: &ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::RSA_PSS_SHA256]
    }
}

#[tokio::main]
async fn main(){

    // Generate self-signed certificate
    let subject_alt_names = vec!["localhost".to_string()];
    let alg = &rcgen::PKCS_RSA_SHA512;
    let key_pair = KeyPair::generate_for(alg).unwrap();
    let cert = CertificateParams::new(subject_alt_names)
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();

    // Write to cert.pem and key.pem
    let mut cert_file = File::create("cert.pem").unwrap();
    let mut key_file = File::create("key.pem").unwrap();

    // Write the serialized certificates and pem files
    writeln!(cert_file, "{}", cert.pem()).unwrap();
    writeln!(key_file, "{}", key_pair.serialize_pem()).unwrap();

    // Proceed with the test
    let cert_path = PathBuf::from("cert.pem");
    let key_path = PathBuf::from("key.pem");
    let server_addr = "127.0.0.1:5001";

    // Create a channel to communicate with the server
    let (tx, rx) = channel();

    // Start server in background that runs on TLS
    let server = tokio::spawn(async move {
        start_tls_server(PathBuf::from("cert.pem"), key_path, server_addr,tx)
            .await
            .unwrap();
    });

    // Parse the certificate into DER format
    let certificates = certs(&mut BufReader::new(File::open(cert_path).unwrap()))
        .next()
        .unwrap()
        .unwrap();

    // Load the certificate into the root store
    let mut cert_store = rustls::RootCertStore::empty();
    cert_store.add(certificates).unwrap();

    // Prepare the client TLS configuration with no client authentication and the root certificate
    let mut config = ClientConfig::builder()
        .with_root_certificates(cert_store)
        .with_no_client_auth();

    // Disable server certificate verification
    let verifier = Arc::new(NoVerification);
    config.dangerous().set_certificate_verifier(verifier);

    // Create a DNS name for the server
    let dns_name = ServerName::try_from("localhost").unwrap();
    let connector = TlsConnector::from(Arc::new(config));

    // Wait for the server to be ready
    rx.await.unwrap();

    // Connect and upgrade the client connection
    let stream = TcpStream::connect(server_addr).await.unwrap();
    let mut tls_stream = connector.connect(dns_name, stream).await.unwrap();

    // Send and receive message
    let message = b"Hello Server!";
    tls_stream.write_all(message).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Read the response from the server
    let mut buffer = vec![0u8; 1024];
    let n = tls_stream.read(&mut buffer).await.unwrap();

    // Check if the response has a length greater than 0
    assert!(n > 0);

    log::info!("Received from server: {:?}", String::from_utf8_lossy(&buffer[..n]));

    // Check if the response is correct
    assert_eq!(&buffer[..n], b"Hello TLS client!");

    // Await server task to conclude
    server.await.unwrap();

    // Delete the certificates
    remove_file("cert.pem").unwrap();
    remove_file("key.pem").unwrap();
}
```

## License
This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more details.