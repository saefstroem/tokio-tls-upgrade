use std::{
    io,
    path::PathBuf, sync::Arc,
};

use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::certificates::{load_certs, load_key};

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