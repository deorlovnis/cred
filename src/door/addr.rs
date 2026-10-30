//! Where the proxy may connect: which names the box's policy allows, and which addresses are
//! public. cred resolves names itself and connects only to a public address it has checked,
//! so a name that points at the router, this Mac or a cloud metadata service leads nowhere.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::ClientConfig;
use url::Url;

use super::tls;
use crate::policy::Site;

pub const HTTPS_PORT: u16 = 443;
/// Per address; a name with several addresses is tried address by address, up to `MAX_TRIES`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_TRIES: usize = 3;

/// IPv4 ranges that aren't public: network, prefix length.
const NON_PUBLIC_V4: [([u8; 4], u8); 15] = [
    ([0, 0, 0, 0], 8),       // "this network"
    ([10, 0, 0, 0], 8),      // private
    ([100, 64, 0, 0], 10),   // carrier-grade NAT
    ([127, 0, 0, 0], 8),     // loopback
    ([169, 254, 0, 0], 16),  // link-local, cloud metadata
    ([172, 16, 0, 0], 12),   // private
    ([192, 0, 0, 0], 24),    // IETF protocol assignments
    ([192, 0, 2, 0], 24),    // documentation
    ([192, 88, 99, 0], 24),  // 6to4 relay anycast
    ([192, 168, 0, 0], 16),  // private
    ([198, 18, 0, 0], 15),   // benchmarking
    ([198, 51, 100, 0], 24), // documentation
    ([203, 0, 113, 0], 24),  // documentation
    ([224, 0, 0, 0], 4),     // multicast
    ([240, 0, 0, 0], 4),     // reserved, and the broadcast address
];

/// Whether cred may connect to the address on a box's behalf. Only global unicast addresses
/// pass, so every IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d) form is refused
/// along with loopback, unique-local, link-local and multicast IPv6. The one translation
/// prefix let through is NAT64's 64:ff9b::/96, and only for a public IPv4 address inside it.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let bits = u32::from(ip);
    !NON_PUBLIC_V4.iter().any(|&(net, prefix)| {
        let mask = u32::MAX << (32 - prefix);
        bits & mask == u32::from(Ipv4Addr::from(net))
    })
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return is_public_v4(Ipv4Addr::new((s[6] >> 8) as u8, s[6] as u8, (s[7] >> 8) as u8, s[7] as u8));
    }
    // Global unicast is 2000::/3; everything else (::, ::1, mapped, ULA, link-local,
    // multicast, 100::/64, local-use NAT64, ...) is out.
    if s[0] & 0xe000 != 0x2000 {
        return false;
    }
    !matches!(
        (s[0], s[1]),
        (0x2001, 0..0x0200)    // 2001::/23 protocol assignments, Teredo
        | (0x2001, 0x0db8)                         // documentation
        | (0x2002, _)                              // 6to4: embeds any IPv4 address
        | (0x3fff, 0..0x1000)
    ) // documentation (3fff::/20)
}

/// The names a box may reach: `"*"` (any host), `https://host` or `https://*.domain`, matched
/// the way a policy's browser origins are.
pub struct Allow(Vec<Site>);

impl Allow {
    pub fn parse(entries: &[String]) -> Result<Self> {
        let sites = entries.iter().map(|e| Site::parse(e).with_context(|| format!("[net] allow '{e}'"))).collect::<Result<_>>()?;
        Ok(Self(sites))
    }

    /// Whether the host (as `clean_host` returns it) may be connected to on port 443.
    pub fn allows(&self, host: &str) -> bool {
        let authority = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        let Ok(url) = Url::parse(&format!("https://{authority}")) else { return false };
        let origin = url.origin().ascii_serialization();
        self.0.iter().any(|s| s.matches(&origin))
    }
}

/// The host and port of a CONNECT target (`host:port`, `[v6]:port`), with the host in the form
/// the rest of the door uses: lower case, no trailing dot, IPv6 without brackets. `None` if the
/// target isn't that, or the host has characters no DNS name has.
pub fn split_target(target: &str) -> Option<(String, u16)> {
    let (host, port) = match target.strip_prefix('[') {
        Some(rest) => {
            let (host, after) = rest.split_once(']')?;
            (host, after.strip_prefix(':')?)
        }
        None => target.rsplit_once(':').filter(|(host, _)| !host.contains(':'))?,
    };
    Some((clean_host(host)?, port.parse().ok()?))
}

fn clean_host(raw: &str) -> Option<String> {
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip.to_string());
    }
    let host = raw.strip_suffix('.').unwrap_or(raw).to_ascii_lowercase();
    let label_ok = |l: &str| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    (host.len() <= 253 && host.split('.').all(label_ok)).then_some(host)
}

/// Why no connection was made.
#[derive(Debug, PartialEq)]
pub enum Refusal {
    /// The name resolved to nothing, or not at all.
    Unresolved(String),
    /// It resolved, but only to addresses that aren't public.
    NotPublic,
    /// Public addresses, none of which answered.
    Unreachable(String),
}

impl Refusal {
    /// The word the log gives for the decision.
    pub fn decision(&self) -> &'static str {
        match self {
            Refusal::Unresolved(_) => "failed:resolve",
            Refusal::NotPublic => "blocked:not-public",
            Refusal::Unreachable(_) => "failed:connect",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Refusal::Unresolved(e) => format!("can't resolve the name: {e}"),
            Refusal::NotPublic => "the name doesn't resolve to a public address".into(),
            Refusal::Unreachable(e) => format!("can't connect: {e}"),
        }
    }
}

type Resolve = Box<dyn Fn(&str) -> io::Result<Vec<IpAddr>> + Send + Sync>;
type Dial = Box<dyn Fn(SocketAddr) -> io::Result<TcpStream> + Send + Sync>;

/// How the door reaches the internet. Tests swap in their own to reach a local server.
pub struct Net {
    resolve: Resolve,
    dial: Dial,
    /// TLS to the sites (see `tls`): webpki's roots. Only tests change them.
    tls: Arc<ClientConfig>,
}

impl Net {
    pub fn system() -> Self {
        Self {
            resolve: Box::new(|host| Ok((host, HTTPS_PORT).to_socket_addrs()?.map(|a| a.ip()).collect())),
            dial: Box::new(|addr| {
                let stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
                stream.set_nodelay(true)?;
                Ok(stream)
            }),
            tls: tls::client_config(),
        }
    }

    #[cfg(test)]
    pub fn new(resolve: Resolve, dial: Dial) -> Self {
        Self { resolve, dial, tls: tls::client_config() }
    }

    /// The TLS settings for connections to the sites.
    pub fn tls(&self) -> &Arc<ClientConfig> {
        &self.tls
    }

    /// Trust only these roots for the sites, so a test can have a site of its own.
    #[cfg(test)]
    pub fn trusting(mut self, roots: rustls::RootCertStore) -> Self {
        self.tls = tls::client_config_trusting(roots);
        self
    }

    /// Connect to the host on port 443, at one of its public addresses and no other. The name
    /// is resolved once; the address that was checked is the address that is dialed.
    pub fn connect(&self, host: &str) -> Result<(TcpStream, IpAddr), Refusal> {
        let addresses = match host.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => (self.resolve)(host).map_err(|e| Refusal::Unresolved(e.to_string()))?,
        };
        if addresses.is_empty() {
            return Err(Refusal::Unresolved("no addresses".into()));
        }
        let public: Vec<IpAddr> = addresses.into_iter().filter(|&ip| is_public(ip)).take(MAX_TRIES).collect();
        if public.is_empty() {
            return Err(Refusal::NotPublic);
        }
        let mut last = String::new();
        for ip in public {
            match (self.dial)(SocketAddr::new(ip, HTTPS_PORT)) {
                Ok(stream) => return Ok((stream, ip)),
                Err(e) => last = e.to_string(),
            }
        }
        Err(Refusal::Unreachable(last))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    fn public(s: &str) -> bool {
        is_public(s.parse().unwrap())
    }

    #[test]
    fn public_ipv4_addresses_pass() {
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "93.184.216.34",
            "140.82.112.3",
            "172.15.255.255",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "192.0.1.1",
            "192.169.0.1",
            "223.255.255.255",
        ] {
            assert!(public(ip), "{ip} should be public");
        }
    }

    #[test]
    fn non_public_ipv4_addresses_are_refused() {
        for ip in [
            "0.0.0.0",
            "0.1.2.3",
            "10.0.0.1",
            "10.255.255.255",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "169.254.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "192.168.255.255",
            "198.18.0.1",
            "198.19.255.255",
            "198.51.100.7",
            "203.0.113.9",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public(ip), "{ip} should be refused");
        }
    }

    #[test]
    fn public_ipv6_addresses_pass() {
        for ip in ["2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4001::200e", "2001:200::1", "3fff:1000::1"] {
            assert!(public(ip), "{ip} should be public");
        }
    }

    #[test]
    fn non_public_ipv6_addresses_are_refused() {
        for ip in [
            "::",
            "::1",
            "fe80::1",
            "fe80::1%1",
            "fc00::1",
            "fd12:3456::1",
            "fec0::1",
            "ff02::1",
            "ff00::",
            "100::1",
            "2001::1",
            "2001:0:4136:e378:8000:63bf:3fff:fdd2",
            "2001:1::1",
            "2001:db8::1",
            "2002::1",
            "2002:7f00:1::1",
            "2002:a00:1::",
            "3fff::1",
            "3fff:fff::1",
            "5f00::1",
            "64:ff9b:1::1",
            "1::1",
            "4000::1",
            "8000::1",
        ] {
            let parsed: Result<IpAddr, _> = ip.parse();
            // A zone id isn't an address at all, so it can't pass either.
            assert!(parsed.map_or(true, |p| !is_public(p)), "{ip} should be refused");
        }
    }

    #[test]
    fn ipv4_mapped_and_compatible_forms_are_refused() {
        for ip in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:192.168.1.1",
            "::ffff:169.254.169.254",
            "::ffff:8.8.8.8",
            "::ffff:0:0",
            "::127.0.0.1",
            "::10.0.0.1",
            "::8.8.8.8",
            "::0.0.0.2",
        ] {
            assert!(!public(ip), "{ip} should be refused");
        }
    }

    #[test]
    fn nat64_passes_only_a_public_address_inside() {
        assert!(public("64:ff9b::808:808"));
        assert!(public("64:ff9b::5db8:d822"));
        for ip in ["64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b::c0a8:1", "64:ff9b::a9fe:a9fe", "64:ff9b::6440:1", "64:ff9b::", "64:ff9b::e000:1"] {
            assert!(!public(ip), "{ip} should be refused");
        }
    }

    fn allow(entries: &[&str]) -> Allow {
        Allow::parse(&entries.iter().map(|e| e.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn star_allows_any_host() {
        let a = allow(&["*"]);
        assert!(a.allows("example.com") && a.allows("a.b.example.com") && a.allows("93.184.216.34") && a.allows("2606:4700::1111"));
    }

    #[test]
    fn exact_entry_allows_just_that_host() {
        let a = allow(&["https://api.example.com"]);
        assert!(a.allows("api.example.com"));
        assert!(!a.allows("example.com") && !a.allows("x.api.example.com") && !a.allows("api.example.com.evil.com") && !a.allows("evilapi.example.com"));
    }

    #[test]
    fn wildcard_entry_allows_the_domain_and_its_subdomains() {
        let a = allow(&["https://*.wikipedia.org"]);
        assert!(a.allows("en.wikipedia.org") && a.allows("a.b.wikipedia.org") && a.allows("wikipedia.org"));
        assert!(!a.allows("notwikipedia.org") && !a.allows("wikipedia.org.evil.com") && !a.allows("wikipedia.com"));
    }

    #[test]
    fn nothing_is_allowed_without_entries() {
        assert!(!allow(&[]).allows("example.com"));
    }

    #[test]
    fn bad_entries_are_rejected_with_their_text() {
        for entry in ["example.com", "https://*.com", "ftp://*.example.com", "https://example.com/path"] {
            let err = Allow::parse(&[entry.to_string()]).err().unwrap_or_else(|| panic!("{entry} should fail"));
            assert!(format!("{err:#}").contains(entry), "{err:#}");
        }
    }

    #[test]
    fn targets_split_into_a_clean_host_and_port() {
        let t = |s: &str| split_target(s);
        assert_eq!(t("Example.COM:443"), Some(("example.com".into(), 443)));
        assert_eq!(t("example.com.:443"), Some(("example.com".into(), 443)));
        assert_eq!(t("1.2.3.4:443"), Some(("1.2.3.4".into(), 443)));
        assert_eq!(t("[2606:4700::1111]:443"), Some(("2606:4700::1111".into(), 443)));
        assert_eq!(t("example.com:8443"), Some(("example.com".into(), 8443)));
        for bad in [
            "example.com",
            "example.com:",
            "example.com:abc",
            "example.com:99999",
            ":443",
            "[::1:443",
            "::1:443",
            "a b.com:443",
            "a/b.com:443",
            "user@evil.com:443",
            "exa%6dple.com:443",
            "..:443",
            "a..b:443",
            "-.com:443x",
        ] {
            assert_eq!(t(bad), None, "{bad}");
        }
    }

    fn local_listener() -> (TcpListener, SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        (l, addr)
    }

    /// A Net that resolves every name to `ips` and records the addresses it was asked to dial,
    /// handing back a connection to `server` each time.
    fn fake_net(ips: Vec<&str>, server: SocketAddr) -> (Net, Arc<Mutex<Vec<SocketAddr>>>) {
        let dialed = Arc::new(Mutex::new(Vec::new()));
        let log = dialed.clone();
        let ips: Vec<IpAddr> = ips.iter().map(|s| s.parse().unwrap()).collect();
        let net = Net::new(
            Box::new(move |_| Ok(ips.clone())),
            Box::new(move |addr| {
                log.lock().unwrap().push(addr);
                TcpStream::connect(server)
            }),
        );
        (net, dialed)
    }

    #[test]
    fn connects_only_to_the_public_address_it_vetted() {
        let (_server, addr) = local_listener();
        let (net, dialed) = fake_net(vec!["10.0.0.5", "127.0.0.1", "93.184.216.34", "192.168.1.1"], addr);
        let (_, ip) = net.connect("example.com").unwrap();
        assert_eq!(ip, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(*dialed.lock().unwrap(), vec![SocketAddr::new(ip, 443)]);
    }

    #[test]
    fn a_name_that_resolves_only_to_private_addresses_is_refused_without_dialing() {
        let (_server, addr) = local_listener();
        let (net, dialed) = fake_net(vec!["127.0.0.1", "10.1.2.3", "::1", "::ffff:192.168.0.1", "169.254.169.254"], addr);
        assert_eq!(net.connect("rebind.example.com").err(), Some(Refusal::NotPublic));
        assert!(dialed.lock().unwrap().is_empty());
    }

    #[test]
    fn ip_literals_are_vetted_too() {
        let (_server, addr) = local_listener();
        let (net, dialed) = fake_net(vec!["93.184.216.34"], addr);
        for ip in ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:7f00:1", "fe80::1"] {
            assert_eq!(net.connect(ip).err(), Some(Refusal::NotPublic), "{ip}");
        }
        assert!(dialed.lock().unwrap().is_empty());
        // A public literal is dialed as it is; the resolver isn't asked.
        assert_eq!(net.connect("1.2.3.4").unwrap().1, "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn resolution_failures_and_empty_answers_are_refused() {
        let (_server, addr) = local_listener();
        let (net, _) = fake_net(vec![], addr);
        assert!(matches!(net.connect("nothing.example.com"), Err(Refusal::Unresolved(_))));
        let failing = Net::new(Box::new(|_| Err(io::Error::other("no such host"))), Box::new(|_| unreachable!()));
        assert!(matches!(failing.connect("x.example.com"), Err(Refusal::Unresolved(e)) if e.contains("no such host")));
    }

    #[test]
    fn tries_the_next_public_address_when_one_does_not_answer() {
        let (_server, addr) = local_listener();
        let tried = Arc::new(Mutex::new(Vec::new()));
        let log = tried.clone();
        let net = Net::new(
            Box::new(|_| Ok(vec!["1.1.1.1".parse().unwrap(), "8.8.8.8".parse().unwrap()])),
            Box::new(move |a| {
                log.lock().unwrap().push(a.ip());
                if a.ip() == "1.1.1.1".parse::<IpAddr>().unwrap() { Err(io::Error::other("timed out")) } else { TcpStream::connect(addr) }
            }),
        );
        let (_, ip) = net.connect("example.com").unwrap();
        assert_eq!(ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(tried.lock().unwrap().len(), 2);
    }

    #[test]
    fn unreachable_public_addresses_report_the_last_error() {
        let net = Net::new(Box::new(|_| Ok(vec!["1.1.1.1".parse().unwrap()])), Box::new(|_| Err(io::Error::other("timed out"))));
        assert_eq!(net.connect("example.com").err(), Some(Refusal::Unreachable("timed out".into())));
    }
}
