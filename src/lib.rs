mod certificates;
mod upgrade;

pub use upgrade::upgrade_tcp_stream;
#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::ClientConfig;
    use rustls_pemfile::certs;
    use std::fs::File;
    use std::io::BufReader;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::io::{self};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::runtime::Runtime;
    use tokio_rustls::TlsConnector;
    async fn start_tls_server(
        certificate_path: PathBuf,
        key_path: PathBuf,
        addr: &str,
    ) -> io::Result<()> {
        let listener = TcpListener::bind(addr).await?;
        let (stream, _) = listener.accept().await?;
        let mut tls_stream = upgrade_tcp_stream(stream, certificate_path, key_path).await?;

        // Handle the stream: for example, read a message and respond
        let mut buffer = [0u8; 1024]; // Example buffer
        let n = tls_stream.read(&mut buffer).await?;
        if n > 0 {
            let response = b"Hello TLS client!";
            tls_stream.write_all(response).await?;
        }

        Ok(())
    }
   

    #[tokio::test]
    async fn test_tls_upgrade() {
        let cert_path = PathBuf::from("cert.pem");
        let key_path = PathBuf::from("key.pem");
        let server_addr = "127.0.0.1:5001";

        // Start server in background
        let server = tokio::spawn(async move {
            start_tls_server(PathBuf::from("cert.pem"), key_path, server_addr)
                .await
                .unwrap();
        });
        let certificates=certs(&mut BufReader::new(File::open(cert_path).unwrap())).next().unwrap().unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await; // wait for the server to be ready

        let mut cert_store= rustls::RootCertStore::empty();
        cert_store.add(certificates).unwrap();

        // Prepare the client TLS configuration
        let config = ClientConfig::builder()
            .with_root_certificates(cert_store)
            .with_no_client_auth();

        let dns_name = ServerName::try_from("localhost").unwrap();
        let connector = TlsConnector::from(Arc::new(config));

        // Connect and upgrade the client connection
        let stream = TcpStream::connect(server_addr).await.unwrap();
        let mut tls_stream = connector.connect(dns_name, stream).await.unwrap();

        // Send and receive message
        let message = b"Hello Server!";
        tls_stream.write_all(message).await.unwrap();
        tls_stream.flush().await.unwrap();

        let mut buffer = vec![0u8; 1024];
        let n = tls_stream.read(&mut buffer).await.unwrap();
        assert!(n > 0);
        assert_eq!(&buffer[..n], b"Hello TLS client!");

        // Await server task to conclude
        server.await.unwrap();
    }
}
