//! TLS at the door. The box's tools trust one CA, made for this box alone; the door answers the
//! tool's TLS with a certificate for the site it asked for, signed by that CA, and speaks TLS
//! to the real site itself, with full verification (webpki's roots, the site's name, no
//! exceptions). What flows between the two is plain HTTP/1.1 that the door can read.
//!
//! The CA's key lives in memory while the box runs and is sealed in the store (see `seal`)
//! otherwise; no VM mounts the folder it is in. A box can only be fooled by its own door, since
//! no other box and no site has a certificate this CA signed.
//!
//! A `Tls` is a handle to one TLS session over two raw halves. Clones share the session, so one
//! thread can read while another writes (rustls itself would want `&mut` for both).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256};
use rustls::crypto::{CryptoProvider, ring};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::seal;

/// What the CA's key is sealed for; `seal::derive(box_key, PURPOSE)` is its key.
pub const PURPOSE: &str = "ca";
const CA_YEARS: i64 = 10;
/// A certificate for a site is valid this long, and replaced after `LEAF_REUSE`. Both start a
/// day in the past, so a VM clock a little behind doesn't matter.
const LEAF_DAYS: i64 = 30;
const LEAF_REUSE: Duration = Duration::from_secs(7 * 24 * 3600);
/// Certificates kept for sites; a box that visits more starts over, so a tool that makes up
/// names can't grow this without end.
const MAX_LEAVES: usize = 1024;
/// How long the TLS handshake with the site may take.
const HANDSHAKE: Duration = Duration::from_secs(20);
/// The only protocol the door speaks. h2 is never offered, on either side.
const ALPN: &[u8] = b"http/1.1";

fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// A box's CA: the certificate its VM trusts, and the key that signs a certificate per site.
pub struct BoxCa {
    name: String,
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    leaves: Mutex<HashMap<String, (Instant, Arc<ServerConfig>)>>,
}

/// What is sealed: enough to sign again and to give the VM the same certificate.
#[derive(Serialize, Deserialize)]
struct Stored {
    name: String,
    cert: String,
    key: String,
}

fn ca_params(box_name: &str) -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("cred box {box_name}"));
    params.distinguished_name = dn;
    Ok(params)
}

fn days_from_now(days: i64) -> OffsetDateTime {
    OffsetDateTime::now_utc() + time::Duration::days(days)
}

impl BoxCa {
    /// A new CA for the box: EC P-256, valid ten years, `CN = cred box <name>`.
    pub fn generate(box_name: &str) -> Result<BoxCa> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("making the box CA's key")?;
        let mut params = ca_params(box_name)?;
        params.not_before = days_from_now(-1);
        params.not_after = days_from_now(CA_YEARS * 365);
        let cert_pem = params.self_signed(&key).context("making the box CA")?.pem();
        Ok(Self::new(box_name, cert_pem, params, key))
    }

    fn new(name: &str, cert_pem: String, params: CertificateParams, key: KeyPair) -> BoxCa {
        BoxCa { name: name.to_string(), cert_pem, issuer: Issuer::new(params, key), leaves: Mutex::new(HashMap::new()) }
    }

    /// The CA as bytes for the store: sealed with `key` (see `seal::derive(box_key, PURPOSE)`).
    pub fn to_sealed(&self, key: &[u8; 32]) -> Result<Vec<u8>> {
        let stored = Stored { name: self.name.clone(), cert: self.cert_pem.clone(), key: self.issuer.key().serialize_pem() };
        Ok(seal::seal(key, PURPOSE, &serde_json::to_vec(&stored)?))
    }

    pub fn from_sealed(sealed: &[u8], key: &[u8; 32]) -> Result<BoxCa> {
        let stored: Stored = serde_json::from_slice(&seal::open(key, PURPOSE, sealed)?).context("reading the box CA")?;
        let signing_key = KeyPair::from_pem(&stored.key).context("reading the box CA's key")?;
        Ok(Self::new(&stored.name, stored.cert, ca_params(&stored.name)?, signing_key))
    }

    /// The certificate the VM trusts (PEM).
    pub fn cert_pem(&self) -> String {
        self.cert_pem.clone()
    }

    /// The TLS settings that present a certificate for `host`, made when first asked and then
    /// reused. ALPN is http/1.1 only.
    pub(super) fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let mut leaves = locked(&self.leaves);
        if let Some((made, config)) = leaves.get(host)
            && made.elapsed() < LEAF_REUSE
        {
            return Ok(config.clone());
        }
        let config = Arc::new(self.issue(host)?);
        if leaves.len() >= MAX_LEAVES {
            leaves.clear();
        }
        leaves.insert(host.to_string(), (Instant::now(), config.clone()));
        Ok(config)
    }

    fn issue(&self, host: &str) -> Result<ServerConfig> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        // The host is a DNS name or an IP address; rcgen tells them apart.
        let mut params = CertificateParams::new(vec![host.to_string()]).with_context(|| format!("a certificate for {host}"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host.chars().take(64).collect::<String>());
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        params.not_before = days_from_now(-1);
        params.not_after = days_from_now(LEAF_DAYS);
        let cert = params.signed_by(&key, &self.issuer)?;
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let mut config =
            ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?.with_no_client_auth().with_single_cert(vec![cert.der().clone()], key)?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        Ok(config)
    }
}

/// The settings for TLS to the real sites: webpki's roots, ALPN http/1.1.
pub fn client_config() -> Arc<ClientConfig> {
    client_config_with(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
}

fn client_config_with(roots: RootCertStore) -> Arc<ClientConfig> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Arc::new(config)
}

/// Settings that trust only these roots. For tests, which have a site of their own.
#[cfg(test)]
pub fn client_config_trusting(roots: RootCertStore) -> Arc<ClientConfig> {
    client_config_with(roots)
}

/// Be the TLS server for the guest's connection (already past its CONNECT), with a certificate
/// for `host`. Returns once the handshake is done. The caller bounds the wait with a timeout on
/// the raw reader.
pub fn accept(ca: &BoxCa, host: &str, reader: impl Read + Send + 'static, writer: impl Write + Send + 'static) -> Result<Tls> {
    let conn = ServerConnection::new(ca.server_config(host)?)?;
    Tls::handshake(Connection::Server(conn), Box::new(reader), Box::new(writer)).context("TLS with the guest")
}

/// Be the TLS client to the real site over `tcp`: SNI and certificate checked against `host`.
/// Returns once the handshake is done, so a site whose certificate doesn't verify is an error
/// here, before the guest is told anything.
pub fn connect(client: &Arc<ClientConfig>, host: &str, tcp: TcpStream) -> Result<Tls> {
    let name = ServerName::try_from(host.to_string()).map_err(|_| anyhow!("{host} isn't a valid server name"))?;
    let conn = ClientConnection::new(client.clone(), name)?;
    tcp.set_read_timeout(Some(HANDSHAKE))?;
    tcp.set_write_timeout(Some(HANDSHAKE))?;
    let tls = Tls::handshake(Connection::Client(conn), Box::new(tcp.try_clone()?), Box::new(tcp.try_clone()?)).context("TLS with the site")?;
    tcp.set_read_timeout(None)?;
    tcp.set_write_timeout(None)?;
    Ok(tls)
}

/// The session and its two raw halves. Waiting on the socket never happens while `conn` is held,
/// so a read that waits for the peer, or a write that waits for room, doesn't stop the other
/// direction. What the session wants to send is moved to `pending` under `conn` and written
/// out under `raw_out` afterwards, in the order it was moved.
struct Inner {
    conn: Mutex<Connection>,
    raw_in: Mutex<Box<dyn Read + Send>>,
    /// Bytes read from `raw_in` that the session couldn't take yet (see `read`).
    held: Mutex<Vec<u8>>,
    pending: Mutex<Vec<u8>>,
    raw_out: Mutex<Box<dyn Write + Send>>,
}

/// One TLS session, as plain `Read` and `Write`. Clones are handles to the same session.
#[derive(Clone)]
pub struct Tls(Arc<Inner>);

/// Both raw halves as one, for `complete_io` during the handshake.
struct Pair<'a>(&'a mut dyn Read, &'a mut dyn Write);

impl Read for Pair<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Pair<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.1.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.1.flush()
    }
}

impl Tls {
    fn handshake(mut conn: Connection, mut raw_in: Box<dyn Read + Send>, mut raw_out: Box<dyn Write + Send>) -> Result<Tls> {
        // Nothing is held back: what the peer sent is read out before more is taken from the
        // socket, and writes are accepted whole.
        conn.set_buffer_limit(None);
        while conn.is_handshaking() {
            if let Err(e) = conn.complete_io(&mut Pair(&mut *raw_in, &mut *raw_out)) {
                // An alert may be waiting for the peer.
                let _ = conn.write_tls(&mut raw_out);
                return Err(e.into());
            }
        }
        while conn.wants_write() {
            conn.write_tls(&mut raw_out)?;
        }
        raw_out.flush()?;
        Ok(Tls(Arc::new(Inner { conn: Mutex::new(conn), raw_in: Mutex::new(raw_in), held: Mutex::new(Vec::new()), pending: Mutex::new(Vec::new()), raw_out: Mutex::new(raw_out) })))
    }

    /// What was agreed with the peer, e.g. `http/1.1`.
    #[cfg(test)]
    pub fn alpn(&self) -> Option<Vec<u8>> {
        locked(&self.0.conn).alpn_protocol().map(<[u8]>::to_vec)
    }

    /// Tell the peer no more is coming (TLS close_notify). Reading still works.
    pub fn finish(&self) -> io::Result<()> {
        let mut conn = locked(&self.0.conn);
        conn.send_close_notify();
        self.queue(&mut conn)?;
        drop(conn);
        self.send()
    }

    /// Move what the session has to send to the queue; whether there was anything. Called with
    /// `conn` held.
    fn queue(&self, conn: &mut Connection) -> io::Result<bool> {
        let mut pending = locked(&self.0.pending);
        let before = pending.len();
        while conn.wants_write() {
            conn.write_tls(&mut *pending)?;
        }
        Ok(pending.len() > before)
    }

    /// Write out the queue, which may include what other handles queued. Returns once
    /// everything queued before this call has been written, by this call or by another.
    fn send(&self) -> io::Result<()> {
        let mut out = locked(&self.0.raw_out);
        let bytes = std::mem::take(&mut *locked(&self.0.pending));
        if !bytes.is_empty() {
            out.write_all(&bytes)?;
        }
        out.flush()
    }
}

impl Read for Tls {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut raw = [0u8; 16 * 1024];
        loop {
            {
                let mut conn = locked(&self.0.conn);
                match conn.reader().read(buf) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    done => return done,
                }
            }
            // Bytes held back last time go in before more is read from the socket.
            let held = std::mem::take(&mut *locked(&self.0.held));
            let mut chunk: &[u8] = if held.is_empty() {
                let n = match locked(&self.0.raw_in).read(&mut raw) {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                if n == 0 {
                    // The end of the stream: the next read says whether it was a clean close.
                    locked(&self.0.conn).read_tls(&mut io::empty())?;
                    continue;
                }
                &raw[..n]
            } else {
                &held
            };
            let mut conn = locked(&self.0.conn);
            // rustls keeps at most 16 KiB of plaintext and refuses more input until it is read,
            // and one full record is that much. So input stops once there is plaintext, and the
            // rest is held for the next call, after the caller has read it.
            while !chunk.is_empty() {
                conn.read_tls(&mut chunk)?;
                match conn.process_new_packets() {
                    Ok(state) if state.plaintext_bytes_to_read() > 0 => break,
                    Ok(_) => {}
                    Err(e) => {
                        let _ = self.queue(&mut conn);
                        drop(conn);
                        let _ = self.send();
                        return Err(io::Error::new(io::ErrorKind::InvalidData, e));
                    }
                }
            }
            if !chunk.is_empty() {
                *locked(&self.0.held) = chunk.to_vec();
            }
            // Answers to what was read (key updates, alerts) go out now. Nothing waits for a
            // write that has nothing to do with it.
            let answers = self.queue(&mut conn)?;
            drop(conn);
            if answers {
                self.send()?;
            }
        }
    }
}

impl Write for Tls {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut conn = locked(&self.0.conn);
        let n = conn.writer().write(buf)?;
        self.queue(&mut conn)?;
        drop(conn);
        self.send()?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut conn = locked(&self.0.conn);
        conn.writer().flush()?;
        self.queue(&mut conn)?;
        drop(conn);
        self.send()
    }
}

/// Roots that trust exactly this certificate (PEM). For tests, which play the guest or a site.
#[cfg(test)]
pub fn trust_only(cert_pem: &str) -> RootCertStore {
    use base64::Engine;
    let body: String = cert_pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(body).expect("a PEM certificate");
    let mut roots = RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(der)).expect("a CA certificate");
    roots
}

#[cfg(test)]
mod tests;
