use tokio::io;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::{certs, private_key};
use std::io::{BufReader, ErrorKind};
use std::fs::File;
use std::path::PathBuf;

pub fn load_certs(path: PathBuf) -> io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(File::open(path)?)).collect()
}

pub fn load_key(path: PathBuf) -> io::Result<PrivateKeyDer<'static>> {
    private_key(&mut BufReader::new(File::open(path)?))
        ?
        .ok_or(io::Error::new(
            ErrorKind::Other,
            "No private key found".to_string(),
        ))
}