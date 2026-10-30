use std::net::TcpListener;
use std::os::unix::net::UnixStream;
use std::thread;

use rustls::StreamOwned;

use super::*;

fn guest_config(ca: &BoxCa, alpn: &[&[u8]]) -> Arc<ClientConfig> {
    let mut config =
        ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_root_certificates(trust_only(&ca.cert_pem())).with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
}

/// What a TLS handshake between a client like the guest's tools and `accept` came to: the
/// door's side, the client's (one byte echoed back, or why not), and what the client agreed on.
type Outcome = (Result<Tls>, Result<u8, String>, Option<Vec<u8>>);

/// A client with `config`, asking for `asked`, against `accept` serving a certificate for `served`.
fn handshake(ca: &Arc<BoxCa>, served: &str, asked: &str, config: Arc<ClientConfig>) -> Outcome {
    let (server_end, client_end) = UnixStream::pair().unwrap();
    let (door_ca, host) = (ca.clone(), served.to_string());
    let server = thread::spawn(move || {
        let reader = server_end.try_clone().unwrap();
        let result = accept(&door_ca, &host, reader, server_end);
        if let Ok(tls) = &result {
            let mut tls = tls.clone();
            let mut byte = [0u8; 1];
            if tls.read(&mut byte).is_ok_and(|n| n == 1) {
                let _ = tls.write_all(&byte);
            }
            let _ = tls.finish();
        }
        result
    });
    let name = ServerName::try_from(asked.to_string()).unwrap();
    let mut client = StreamOwned::new(ClientConnection::new(config, name).unwrap(), client_end);
    let outcome = client.write_all(b"x").and_then(|()| client.flush()).and_then(|()| {
        let mut byte = [0u8; 1];
        client.read_exact(&mut byte).map(|()| byte[0])
    });
    let alpn = client.conn.alpn_protocol().map(<[u8]>::to_vec);
    drop(client);
    (server.join().unwrap(), outcome.map_err(|e| e.to_string()), alpn)
}

#[test]
fn a_certificate_for_a_host_verifies_against_the_box_ca_alone() {
    let ca = Arc::new(BoxCa::generate("research").unwrap());
    for host in ["example.com", "en.wikipedia.org", "a_b.example.org", "93.184.216.34", "2606:2800:220:1::1"] {
        let (server, client, alpn) = handshake(&ca, host, host, guest_config(&ca, &[b"http/1.1"]));
        assert_eq!(client, Ok(b'x'), "{host}");
        assert_eq!(server.unwrap().alpn().as_deref(), Some(&b"http/1.1"[..]), "{host}");
        assert_eq!(alpn.as_deref(), Some(&b"http/1.1"[..]), "{host}");
    }
}

#[test]
fn only_http_1_1_is_offered() {
    let ca = Arc::new(BoxCa::generate("research").unwrap());
    // A tool that speaks h2 too is moved to http/1.1.
    let (_, client, alpn) = handshake(&ca, "example.com", "example.com", guest_config(&ca, &[b"h2", b"http/1.1"]));
    assert_eq!((client, alpn.as_deref()), (Ok(b'x'), Some(&b"http/1.1"[..])));
    // One that can only speak h2 doesn't get a connection.
    let (server, client, _) = handshake(&ca, "example.com", "example.com", guest_config(&ca, &[b"h2"]));
    assert!(server.is_err() && client.is_err());
}

#[test]
fn the_wrong_name_or_the_wrong_ca_does_not_verify() {
    let ca = Arc::new(BoxCa::generate("research").unwrap());
    // A certificate for another name.
    let (server, client, _) = handshake(&ca, "a.example.com", "b.example.com", guest_config(&ca, &[b"http/1.1"]));
    assert!(client.unwrap_err().contains("not valid for name"), "names are checked");
    assert!(server.is_err());
    // Another box's CA doesn't vouch for this box's certificates.
    let other = BoxCa::generate("other").unwrap();
    let (_, client, _) = handshake(&ca, "example.com", "example.com", guest_config(&other, &[b"http/1.1"]));
    assert!(client.unwrap_err().contains("UnknownIssuer"));
    assert_ne!(ca.cert_pem(), other.cert_pem());
}

#[test]
fn certificates_are_made_once_per_host() {
    let ca = BoxCa::generate("research").unwrap();
    let first = ca.server_config("example.com").unwrap();
    assert!(Arc::ptr_eq(&first, &ca.server_config("example.com").unwrap()));
    assert!(!Arc::ptr_eq(&first, &ca.server_config("example.org").unwrap()));
    assert_eq!(first.alpn_protocols, [b"http/1.1".to_vec()]);
    // The cache doesn't grow without end.
    for i in 0..MAX_LEAVES + 5 {
        ca.server_config(&format!("h{i}.example.com")).unwrap();
    }
    assert!(locked(&ca.leaves).len() <= MAX_LEAVES);
}

#[test]
fn a_sealed_ca_comes_back_the_same_and_only_with_its_key() {
    let ca = BoxCa::generate("research").unwrap();
    let key = seal::derive(b"box key", PURPOSE);
    let sealed = ca.to_sealed(&key).unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("PRIVATE KEY"));
    assert!(BoxCa::from_sealed(&sealed, &seal::derive(b"other key", PURPOSE)).is_err());
    assert!(BoxCa::from_sealed(&sealed, &seal::derive(b"box key", "log")).is_err());
    let mut tampered = sealed.clone();
    tampered[30] ^= 1;
    assert!(BoxCa::from_sealed(&tampered, &key).is_err());

    // The reloaded CA is the same certificate, and what it signs is trusted by the old one.
    let back = Arc::new(BoxCa::from_sealed(&sealed, &key).unwrap());
    assert_eq!(back.cert_pem(), ca.cert_pem());
    let (_, client, _) = handshake(&back, "example.com", "example.com", guest_config(&ca, &[b"http/1.1"]));
    assert_eq!(client, Ok(b'x'));
}

#[test]
fn the_ca_certificate_is_public_and_parses_as_a_root() {
    let pem = BoxCa::generate("research").unwrap().cert_pem();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"), "{pem}");
    assert!(!pem.contains("PRIVATE"));
    trust_only(&pem);
}

/// A site with a certificate from `signer` for `name`, serving one connection that echoes a
/// byte. Returns the connection to it.
fn site(signer: &BoxCa, name: &str) -> TcpStream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = signer.server_config(name).unwrap();
    thread::spawn(move || {
        if let Ok((tcp, _)) = listener.accept() {
            let mut tls = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
            let mut byte = [0u8; 1];
            if tls.read_exact(&mut byte).is_ok() {
                let _ = tls.write_all(&byte);
            }
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    TcpStream::connect(addr).unwrap()
}

#[test]
fn the_door_checks_the_site_s_certificate_in_full() {
    let sites = BoxCa::generate("sites").unwrap();
    let client = client_config_trusting(trust_only(&sites.cert_pem()));
    let mut tls = connect(&client, "example.com", site(&sites, "example.com")).unwrap();
    tls.write_all(b"z").unwrap();
    let mut byte = [0u8; 1];
    tls.read_exact(&mut byte).unwrap();
    assert_eq!(&byte, b"z");
    assert_eq!(tls.alpn().as_deref(), Some(&b"http/1.1"[..]));

    // A certificate for another name, one from a CA nobody trusts, and the real roots (which
    // don't know this test's CA).
    let e = connect(&client, "example.com", site(&sites, "other.example.com")).err().unwrap();
    assert!(format!("{e:#}").contains("not valid for name"), "{e:#}");
    let rogue = BoxCa::generate("rogue").unwrap();
    let e = connect(&client, "example.com", site(&rogue, "example.com")).err().unwrap();
    assert!(format!("{e:#}").contains("UnknownIssuer"), "{e:#}");
    let e = connect(&client_config(), "example.com", site(&sites, "example.com")).err().unwrap();
    assert!(format!("{e:#}").contains("UnknownIssuer"), "{e:#}");
    // Not a TLS server at all.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let plain = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    thread::spawn(move || {
        if let Ok((mut tcp, _)) = listener.accept() {
            let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
        }
    });
    assert!(connect(&client, "example.com", plain).is_err());
}

#[test]
fn one_thread_can_read_while_another_writes() {
    let ca = Arc::new(BoxCa::generate("research").unwrap());
    let (server_end, client_end) = UnixStream::pair().unwrap();
    let door_ca = ca.clone();
    let server = thread::spawn(move || {
        let reader = server_end.try_clone().unwrap();
        let tls = accept(&door_ca, "example.com", reader, server_end).unwrap();
        // Read 1 MB from the client on one thread while sending 1 MB on another.
        let (mut reader, mut writer) = (tls.clone(), tls.clone());
        let receive = thread::spawn(move || {
            let (mut total, mut buf) = (0, [0u8; 8192]);
            while total < 1 << 20 {
                let n = reader.read(&mut buf).unwrap();
                assert!(n > 0);
                total += n;
            }
            total
        });
        writer.write_all(&vec![7u8; 1 << 20]).unwrap();
        let got = receive.join().unwrap();
        writer.finish().unwrap();
        got
    });
    let name = ServerName::try_from("example.com".to_string()).unwrap();
    let mut client = StreamOwned::new(ClientConnection::new(guest_config(&ca, &[b"http/1.1"]), name).unwrap(), client_end);
    // The client sends and reads from one thread, so it sends in pieces and reads in between;
    // the door side never waits for either to finish first.
    let mut all = Vec::new();
    let mut buf = [0u8; 8192];
    for _ in 0..128 {
        client.write_all(&[9u8; 8192]).unwrap();
        client.flush().unwrap();
        let n = client.read(&mut buf).unwrap();
        all.extend_from_slice(&buf[..n]);
    }
    client.read_to_end(&mut all).unwrap();
    assert_eq!(all.len(), 1 << 20);
    assert!(all.iter().all(|&b| b == 7));
    assert_eq!(server.join().unwrap(), 1 << 20);
}
