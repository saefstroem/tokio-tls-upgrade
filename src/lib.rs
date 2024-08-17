mod certificates;
mod upgrade;

pub use upgrade::upgrade_tcp_stream;
#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
    use rustls_pemfile::certs;
    use std::fs::{remove_file, File};
    use std::io::{BufReader, Write};
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;
    use tokio_rustls::TlsConnector;

    // Start a TLS server that listens on the given address and port
    async fn start_tls_server(
        certificate_path: PathBuf,
        key_path: PathBuf,
        addr: &str,
        tx: oneshot::Sender<u8>,
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
            log::info!(
                "Received from client: {:?}",
                String::from_utf8_lossy(&buffer[..n])
            );
            let response = b"Hello TLS client!";
            tls_stream.write_all(response).await?;
        }

        Ok(())
    }

    // Implement a ServerCertVerifier that does not verify the server certificate for testing purposes
    #[derive(Debug)]
    struct NoVerification;

    // Always return ServerCertVerified::assertion() to indicate that the server certificate is verified
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

    #[tokio::test]
    async fn test_tls_upgrade() {
        env_logger::builder().is_test(true).init();

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
        let (tx, rx) = oneshot::channel();

        // Start server in background that runs on TLS
        let server = tokio::spawn(async move {
            start_tls_server(PathBuf::from("cert.pem"), key_path, server_addr, tx)
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

        // Prepare the client TLS configuration
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

        log::info!(
            "Received from server: {:?}",
            String::from_utf8_lossy(&buffer[..n])
        );

        // Check if the response is correct
        assert_eq!(&buffer[..n], b"Hello TLS client!");

        // Await server task to conclude
        server.await.unwrap();

        // Delete the files
        remove_file("cert.pem").unwrap();
        remove_file("key.pem").unwrap();
    }
}
