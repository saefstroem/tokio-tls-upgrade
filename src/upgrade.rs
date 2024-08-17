use std::{path::PathBuf, sync::Arc};

use crate::certificates::{load_certs, load_key};
use tokio::{io, net::TcpStream};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

/**
## Upgrade an existing tokio TCP stream to a TLS stream
   This function takes a TCP stream and upgrades it to a TLS stream using the given certificate and key files.
   It returns a `TlsStream<TcpStream>` if successful, or an `tokio::io::Error` if the upgrade fails.

### Parameters
- `stream`: A `tokio::net::TcpStream` that will be upgraded to a TLS stream.
- `certificate_path`: A `std::path::PathBuf` containing the path to the certificate file.
- `key_path`: A `std::path::PathBuf` containing the path to the private key file.

### Returns
A `tokio_rustls::server::TlsStream<tokio::net::TcpStream>` if the upgrade is successful, or an `tokio::io::Error` if the upgrade fails.

### Key generation
To generate a self-signed certificate on Linux, you can use the `openssl` command-line tool:
```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
```
This command generates a private key (`key.pem`) and a self-signed certificate (`cert.pem`) valid for 365 days.

For production use, you should obtain a certificate from a trusted certificate authority (CA).

### Example
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
*/
pub async fn upgrade_tcp_stream(
    stream: TcpStream,
    certificate_path: PathBuf,
    key_path: PathBuf,
) -> io::Result<TlsStream<TcpStream>> {
    let cert = load_certs(certificate_path)?;
    let key = load_key(key_path)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tls_stream = acceptor.accept(stream).await?;
    Ok(tls_stream)
}
