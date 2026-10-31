//! Docker in a real agent VM, behind the real door: what a box with `docker = true` can do, and
//! that its containers get no further than the box. Needs the network and Apple's `container`
//! with an agent image that has Docker Engine (box/agent.Containerfile); set
//! `CRED_E2E_AGENT_IMAGE` to test an image built under another name, and `CRED_E2E_JVM_IMAGE` to
//! say which image to run Testcontainers in (without it that test is skipped).
//!
//!     mise run e2e-box        # includes this

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use super::intercept_tests::{Vm, log_lines, sh};
use super::tls::BoxCa;
use super::{Config, Door};
use crate::engine;

/// The bounding capabilities of the shell `sh` runs in the VM, from /proc.
fn bounding_caps(vm: &str) -> u64 {
    let (_, out) = sh(vm, &[], "grep CapBnd /proc/self/status");
    u64::from_str_radix(out.split_whitespace().last().unwrap(), 16).unwrap()
}

/// A box with Docker: the real door with these `allow` rules, the VM, the CA, dockerd. The home
/// folder has what `cred box run` writes there.
struct DockerBox {
    log: PathBuf,
    // Dropped in this order: the VM, then the door.
    _vm: Vm,
    _door: Door,
}

impl DockerBox {
    fn start(name: String, image: String, allow: Vec<String>, memory: &str) -> Self {
        let dir = PathBuf::from(format!("/tmp/{name}"));
        let spec = vm_spec(&name, &image, &dir, memory, true);
        let ca = Arc::new(BoxCa::generate("e2e").unwrap());
        let log = dir.join("log").join("door.log");
        let config = Config {
            name: name.clone(),
            socket: spec.socket.clone(),
            allow,
            model: None,
            sites: vec![],
            net: Default::default(),
            log_key: [9; 32],
            log: log.clone(),
            ca: Some(ca.clone()),
            browser_socket: None,
            browser_tokens: Default::default(),
            browser: None,
        };
        let door = Door::start(config).unwrap();
        let vm = Vm(name.clone());
        engine::run(&spec).unwrap();
        engine::install_ca(&name, &ca.cert_pem()).unwrap();
        let started = Instant::now();
        engine::start_docker(&name).unwrap();
        println!("dockerd answered after {:?}", started.elapsed());
        Self { log, _vm: vm, _door: door }
    }
}

/// A fresh folder for the box, with the home `cred box run` would prepare.
fn box_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(format!("/tmp/{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("home/.docker")).unwrap();
    std::fs::write(dir.join("home/.docker/config.json"), serde_json::json!({ "proxies": engine::docker_proxies() }).to_string()).unwrap();
    dir
}

fn vm_spec(name: &str, image: &str, dir: &Path, memory: &str, docker: bool) -> engine::VmSpec {
    engine::VmSpec {
        name: name.into(),
        image: image.into(),
        cpus: 4,
        memory: memory.into(),
        socket: dir.join(format!("{}.sock", docker as u8)),
        mounts: vec![engine::Mount { host: dir.join("home"), guest: "/home/agent".into(), readonly: false }],
        docker,
        rosetta: false,
    }
}

const CAP_NET_ADMIN: u64 = 1 << 12;
const CAP_SYS_PTRACE: u64 = 1 << 19;
const CAP_SYS_ADMIN: u64 = 1 << 21;

#[test]
#[ignore = "needs Apple's `container`, an agent image with Docker and the internet; run with `mise run e2e-box`"]
fn real_vm_docker_works_through_the_door_and_only_there() {
    if std::env::var_os("CRED_E2E_BOX").is_none() {
        eprintln!("CRED_E2E_BOX isn't set: skipping");
        return;
    }
    engine::available().unwrap();
    let image = engine::image_digest(&std::env::var("CRED_E2E_AGENT_IMAGE").unwrap_or(engine::AGENT_IMAGE.into())).unwrap();
    let name = format!("dkr-{}", std::process::id());
    let dir = box_dir(&name);

    // Without docker = true: no dockerd, and none of its capabilities.
    let plain = format!("{name}-plain");
    let vm = Vm(plain.clone());
    engine::run(&vm_spec(&plain, &image, &dir, "4G", false)).unwrap();
    let caps = bounding_caps(&plain);
    assert_eq!(caps & (CAP_SYS_ADMIN | CAP_NET_ADMIN | CAP_SYS_PTRACE), 0, "CapBnd {caps:x}");
    let (ok, out) = sh(&plain, &[], "docker version");
    assert!(!ok && out.contains("no such file"), "no daemon: {out}");
    assert_eq!(sh(&plain, &[], "cat /proc/[0-9]*/comm | grep -c dockerd").1, "0");
    assert!(!sh(&plain, &[], "grep -q ' /var/lib/docker ' /proc/mounts").0);
    drop(vm);

    let allow = ["registry-1.docker.io", "auth.docker.io", "production.cloudfront.docker.com", "example.com"];
    let running = DockerBox::start(name.clone(), image, allow.iter().map(|h| format!("https://{h}")).collect(), "4G");
    let log = running.log.clone();
    let caps = bounding_caps(&name);
    assert_eq!(caps & (CAP_SYS_ADMIN | CAP_NET_ADMIN | CAP_SYS_PTRACE), CAP_SYS_ADMIN | CAP_NET_ADMIN | CAP_SYS_PTRACE, "CapBnd {caps:x}");
    assert!(sh(&name, &[], "grep -q ' /var/lib/docker tmpfs ' /proc/mounts").0, "Docker's data is in memory");

    let env = engine::agent_env(true);
    let ok = |what: &str, script: &str| {
        let (ok, out) = sh(&name, &env, script);
        println!("--- {what}\n{out}");
        assert!(ok, "{what} failed: {out}");
        out
    };
    let fails = |what: &str, script: &str| {
        let (ok, out) = sh(&name, &env, script);
        println!("--- {what} (must fail)\n{out}");
        assert!(!ok, "{what} should have failed: {out}");
        out
    };

    // The agent uses Docker without root; pulls go through the door, which dockerd trusts.
    ok("agent", "test \"$(id -u)\" = 1000");
    ok("hello-world", "docker run --rm hello-world | grep 'Hello from Docker!'");

    // Testcontainers' way: a published port on a random host port, reached from the VM.
    ok("postgres", "docker run -d --name pg -e POSTGRES_PASSWORD=pw -p 5432 postgres:16-alpine");
    ok("postgres ready", "for i in $(seq 120); do docker exec pg pg_isready -h 127.0.0.1 -U postgres && exit 0; sleep 0.5; done; exit 1");
    let port = ok("mapped port", "docker port pg 5432/tcp | head -n 1 | sed 's/.*://'");
    // Postgres answers an SSLRequest with one byte, N or S.
    let ssl_request =
        format!("python3 -c \"import socket, struct; s = socket.create_connection(('localhost', {port}), 5); s.sendall(struct.pack('!II', 8, 80877103)); print(s.recv(1))\"");
    let answer = ok("connect from the VM", &ssl_request);
    assert!(answer == "b'N'" || answer == "b'S'", "{answer}");

    // Containers get the door's proxy from the Docker CLI, and nothing else.
    let on = |network: &str| format!("docker run --rm --network {network} -v /usr/local/share/ca-certificates/cred-box.crt:/ca.crt:ro curlimages/curl -sS -m 30 --cacert /ca.crt");
    let curl = on("bridge");
    ok("container through the door", &format!("{curl} -o /dev/null -w '%{{http_code}}\\n' https://example.com | grep 200"));
    // a user-defined network (Testcontainers and compose make them) reaches the proxy too
    ok("network", "docker network create other");
    ok("container on another network", &format!("{} -o /dev/null https://example.com", on("other")));
    let out = fails("site outside allow", &format!("{curl} https://www.wikipedia.org"));
    assert!(out.contains("403"), "{out}");
    // The door answers a refused write itself, inside the tunnel.
    let out = ok("a write", &format!("{curl} -X POST -d x https://example.com"));
    assert!(out.contains("doesn't allow POST"), "{out}");
    fails("around the proxy", &format!("{curl} --noproxy '*' -m 5 https://example.com"));
    fails("a public address directly", &format!("{curl} --noproxy '*' -m 5 http://1.1.1.1"));
    fails("the Mac on container's network", &format!("{curl} --noproxy '*' -m 5 http://192.168.64.1"));
    fails("a private address", &format!("{curl} --noproxy '*' -m 5 http://192.168.1.1"));
    fails("the model gateway", &format!("{curl} --noproxy '*' -m 5 http://127.0.0.2/model"));
    assert_eq!(ok("interfaces", "ls /sys/class/net | grep -v -e '^veth' -e '^br-' | tr '\\n' ' '"), "docker0 lo");

    // What Testcontainers and builds ask of the engine beyond a plain container.
    ok("privileged", "docker run --rm --privileged hello-world | grep 'Hello from Docker!'");
    ok("docker build", "printf 'FROM hello-world\\nLABEL built=here\\n' | docker build -t built - && docker image inspect built | grep built");
    ok("nothing kept on the VM's disk", "! test -e /var/lib/containerd");

    let lines = log_lines(&log);
    let allowed: Vec<&str> = lines.iter().filter(|l| l["decision"] == "allowed").filter_map(|l| l["host"].as_str()).collect();
    for host in ["registry-1.docker.io", "auth.docker.io", "example.com"] {
        assert!(allowed.contains(&host), "{host} in {allowed:?}");
    }
    assert!(lines.iter().any(|l| l["host"] == "www.wikipedia.org" && l["decision"] != "allowed"), "{lines:?}");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}

/// What a project's tests do: Gradle fetches through the door, the JVM talks to dockerd over its
/// socket, Testcontainers starts Postgres, Kafka and Ryuk, the JVM connects to their mapped ports
/// on the VM, and Ryuk removes the containers once the JVM is gone.
#[test]
#[ignore = "needs Apple's `container`, a JVM agent image with Docker and the internet; run with `mise run e2e-box`"]
fn real_vm_testcontainers_run_a_database_and_clean_up() {
    let Some(image) = std::env::var_os("CRED_E2E_BOX").and(std::env::var("CRED_E2E_JVM_IMAGE").ok()) else {
        eprintln!("CRED_E2E_BOX or CRED_E2E_JVM_IMAGE isn't set: skipping");
        return;
    };
    engine::available().unwrap();
    let image = engine::image_digest(&image).unwrap();
    let name = format!("dtc-{}", std::process::id());
    let dir = box_dir(&name);
    let project = dir.join("home/project");
    std::fs::create_dir_all(project.join("src/main/java")).unwrap();
    std::fs::write(project.join("settings.gradle"), "rootProject.name = 'tc'\n").unwrap();
    std::fs::write(
        project.join("build.gradle"),
        "plugins { id 'java' }\n\
         repositories { mavenCentral() }\n\
         dependencies {\n\
           implementation 'org.testcontainers:testcontainers-postgresql:2.0.5'\n\
           implementation 'org.testcontainers:testcontainers-kafka:2.0.5'\n\
           implementation 'org.postgresql:postgresql:42.7.7'\n\
           runtimeOnly 'org.slf4j:slf4j-simple:2.0.17'\n\
         }\n\
         tasks.register('probe', JavaExec) { classpath = sourceSets.main.runtimeClasspath; mainClass = 'Main' }\n",
    )
    .unwrap();
    std::fs::write(
        project.join("src/main/java/Main.java"),
        "import java.sql.DriverManager;\n\
         import org.testcontainers.postgresql.PostgreSQLContainer;\n\
         public class Main {\n\
           public static void main(String[] args) throws Exception {\n\
             var pg = new PostgreSQLContainer(\"postgres:16-alpine\");\n\
             pg.start();\n\
             System.out.println(\"url \" + pg.getJdbcUrl());\n\
             try (var c = DriverManager.getConnection(pg.getJdbcUrl(), pg.getUsername(), pg.getPassword());\n\
                  var r = c.createStatement().executeQuery(\"select 6 * 7\")) {\n\
               r.next();\n\
               System.out.println(\"answer \" + r.getInt(1));\n\
             }\n\
             var kafka = new org.testcontainers.kafka.KafkaContainer(\"apache/kafka:3.9.1\");\n\
             kafka.start();\n\
             var broker = java.net.URI.create(\"kafka://\" + kafka.getBootstrapServers().replaceFirst(\".*://\", \"\"));\n\
             new java.net.Socket(broker.getHost(), broker.getPort()).close();\n\
             System.out.println(\"kafka \" + broker);\n\
             System.exit(0); // left running on purpose: this is Ryuk's to clean up\n\
           }\n\
         }\n",
    )
    .unwrap();

    let running = DockerBox::start(name.clone(), image, vec!["*".into()], "6G");
    let env = engine::agent_env(true);
    let ok = |what: &str, script: &str| {
        let started = Instant::now();
        let (ok, out) = sh(&name, &env, script);
        println!("--- {what} ({:?})\n{out}", started.elapsed());
        assert!(ok, "{what} failed: {out}");
        out
    };
    ok(
        "gradle",
        "cd /tmp && curl -fsSL -o gradle.zip https://services.gradle.org/distributions/gradle-9.8.2-bin.zip && python3 -m zipfile -e gradle.zip /tmp/gradle-dist && chmod +x /tmp/gradle-dist/*/bin/gradle",
    );
    let out = ok("testcontainers", "cd ~/project && /tmp/gradle-dist/*/bin/gradle --no-daemon -q probe 2>&1");
    assert!(out.contains("answer 42") && out.contains("kafka kafka://localhost:"), "{out}");
    assert!(out.contains("jdbc:postgresql://localhost:"), "the mapped port is on the VM: {out}");
    assert!(out.contains("testcontainers/ryuk"), "Ryuk ran: {out}");
    ok("ryuk cleans up", "for i in $(seq 60); do test -z \"$(docker ps -q)\" && exit 0; sleep 1; done; docker ps; exit 1");

    drop(running);
    let _ = std::fs::remove_dir_all(&dir);
}
