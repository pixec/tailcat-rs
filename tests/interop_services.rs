//! Interoperability of the services with the Go tailcat client and OpenSSH,
//! through a local dev relay.
//!
//! Needs the binaries `tests/interop.rs` does, named the same way, plus
//! OpenSSH's `ssh`, `scp` and `ssh-keygen`, so the test is ignored by
//! default:
//!
//! ```text
//! TAILCAT_GO=... DERPER=... cargo test -p tailcat-rs --all-features --test interop_services -- --ignored
//! ```

use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tailcat_rs::{
    Config, DerpNode, DerpRegion, ExecHandler, FileServeMode, FileService, PerfHandler, Ports,
    Region, Server, SshHandler, SshOptions,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

const DERP_PORT: u16 = 3340;
const STUN_PORT: u16 = 33478;
const EXEC_PORT: u16 = 7000;

async fn start_relay(derper: &str) -> Child {
    let relay = Command::new(derper)
        .args(["-dev", "-stun-port", &STUN_PORT.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn derper");
    wait_for_port(DERP_PORT).await;
    relay
}

fn binaries() -> (String, String) {
    let go = std::env::var("TAILCAT_GO").expect("TAILCAT_GO must name the Go tailcat binary");
    let derper = std::env::var("DERPER").expect("DERPER must name the derper binary");
    (go, derper)
}

async fn wait_for_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("nothing listening on port {port}");
}

fn dev_region() -> DerpRegion {
    DerpRegion {
        region_id: 1,
        region_code: "dev".into(),
        nodes: vec![DerpNode {
            name: "dev".into(),
            region_id: 1,
            host_name: "127.0.0.1".into(),
            ipv4: "127.0.0.1".into(),
            derp_port: DERP_PORT.into(),
            stun_port: STUN_PORT.into(),
            is_insecure_for_tests: true,
            ..Default::default()
        }],
        ..Default::default()
    }
}

struct Services {
    ssh: Mutex<SshHandler>,
    perf: PerfHandler,
    exec: ExecHandler,
}

async fn go(go: &str, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new(go)
        .env("TS_DEBUG_USE_DERP_HTTP", "1")
        .env("SSH_AUTH_SOCK", "")
        .arg("--key=new")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn tailcat");
    if let Some(input) = stdin {
        let mut w = child.stdin.take().unwrap();
        w.write_all(input).await.unwrap();
        w.shutdown().await.unwrap();
    }
    let out = tokio::time::timeout(Duration::from_secs(90), child.wait_with_output())
        .await
        .unwrap_or_else(|_| panic!("tailcat {args:?} timed out"))
        .unwrap();
    eprintln!(
        "$ tailcat {}\n  exit: {}\n  stdout: {:?}\n  stderr: {:?}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr).trim_end(),
    );
    out
}

async fn openssh(go: &str, addr: &str, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut child = Command::new("ssh")
        .env("TS_DEBUG_USE_DERP_HTTP", "1")
        .env("SSH_AUTH_SOCK", "")
        .env("TERM", "xterm")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "StrictHostKeyChecking no",
            "-o",
            "UserKnownHostsFile /dev/null",
            "-o",
            "LogLevel ERROR",
            "-o",
            "BatchMode yes",
            "-o",
        ])
        .arg(format!("ProxyCommand={go} --key=new {addr} 22"))
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn ssh");
    if let Some(input) = stdin {
        let mut w = child.stdin.take().unwrap();
        w.write_all(input).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        w.shutdown().await.unwrap();
    }
    let out = tokio::time::timeout(Duration::from_secs(90), child.wait_with_output())
        .await
        .expect("ssh timed out")
        .unwrap();
    eprintln!(
        "$ ssh {}\n  exit: {}\n  stdout: {:?}\n  stderr: {:?}",
        args.join(" "),
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr).trim_end(),
    );
    out
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn ssh_handler(host_key: &Path, mut opts: SshOptions) -> SshHandler {
    opts.host_key = Some(host_key.into());
    SshHandler::new(opts).unwrap()
}

fn json_bytes(v: &serde_json::Value, side: &str) -> u64 {
    v[side]["bytes"].as_u64().unwrap_or(0)
}

#[tokio::test]
#[ignore = "needs the Go tailcat CLI, derper and OpenSSH"]
#[allow(clippy::too_many_lines)]
async fn go_client_uses_rust_services() {
    let (go_bin, derper) = binaries();
    let _relay = start_relay(&derper).await;
    let tmp = tempfile::tempdir().unwrap();
    let host_key = tmp.path().join("host_key");

    let services = Arc::new(Services {
        ssh: Mutex::new(ssh_handler(
            &host_key,
            SshOptions {
                shell: true,
                ..Default::default()
            },
        )),
        perf: PerfHandler::new(),
        exec: ExecHandler::new([
            "/bin/sh",
            "-c",
            "echo \"$TAILCAT_PEER_KEY $TAILCAT_LOCAL_ADDR\"; tr a-z A-Z",
        ]),
    });
    let server = Arc::new(
        Server::start(Config {
            region: Region::Embedded(dev_region()),
            is_derp_http_insecure: true,
            tcp_ports: Ports::list([22, tailcat_rs::perf::PORT, EXEC_PORT]),
            udp_ports: Some(Ports::list([tailcat_rs::perf::PORT])),
            ..Default::default()
        })
        .await
        .expect("start server"),
    );
    {
        let (server, services) = (server.clone(), services.clone());
        tokio::spawn(async move {
            while let Some(conn) = server.accept_tcp().await {
                let services = services.clone();
                let peer = conn.peer();
                tokio::spawn(async move {
                    match conn.local_addr().port() {
                        22 => {
                            let ssh = services.ssh.lock().unwrap().clone();
                            let _ = ssh.serve(conn, peer).await;
                        }
                        tailcat_rs::perf::PORT => services.perf.serve_tcp(conn, peer).await,
                        EXEC_PORT => {
                            let _ = services.exec.serve(conn, &peer).await;
                        }
                        _ => {}
                    }
                });
            }
        });
    }
    {
        let (server, services) = (server.clone(), services.clone());
        tokio::spawn(async move {
            while let Some(flow) = server.accept_udp().await {
                let services = services.clone();
                tokio::spawn(async move { services.perf.serve_udp(flow).await });
            }
        });
    }
    let addr = server.tailcat_addr().to_string();
    let addr = addr.as_str();
    let set_ssh = |opts: SshOptions| *services.ssh.lock().unwrap() = ssh_handler(&host_key, opts);

    // tailcat ssh: a shell command and its exit status.
    let out = go(
        &go_bin,
        &["ssh", addr, "echo hello-from-rust; exit 3"],
        None,
    )
    .await;
    assert_eq!(stdout(&out), "hello-from-rust\n");
    assert_eq!(out.status.code(), Some(3));

    // OpenSSH through tailcat as its ProxyCommand: environment, PTY and MOTD.
    let out = openssh(
        &go_bin,
        addr,
        &[
            "-o",
            "SetEnv LANG=C.interop",
            "tc",
            "echo \"$LANG $TAILCAT_PEER_KEY\"",
        ],
        None,
    )
    .await;
    assert!(out.status.success());
    assert!(stdout(&out).starts_with("C.interop nodekey:"));
    let out = openssh(&go_bin, addr, &["-tt", "tc", "tty; echo TERM=$TERM"], None).await;
    let text = stdout(&out);
    assert!(
        text.contains("/dev/") && text.contains("TERM=xterm"),
        "{text}"
    );
    assert!(!text.contains("Connected via tailcat SSH."));
    let out = openssh(
        &go_bin,
        addr,
        &["-tt", "tc"],
        Some(b"echo pty-marker\nexit\n"),
    )
    .await;
    let text = stdout(&out);
    assert!(text.contains("Connected via tailcat SSH."), "{text}");
    assert!(text.contains("pty-marker"), "{text}");

    // tailcat ls over the shell's full-filesystem SFTP.
    let out = go(&go_bin, &["ls", &format!("{addr}:/")], None).await;
    assert!(out.status.success());
    assert!(stdout(&out).lines().any(|l| l == "tmp/" || l == "usr/"));

    // Public-key authentication.
    let key = tmp.path().join("id_ed25519");
    let keygen = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", ""])
        .arg("-f")
        .arg(&key)
        .status()
        .await
        .unwrap();
    assert!(keygen.success());
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    set_ssh(SshOptions {
        shell: true,
        authorized_keys: Some(vec![public]),
        ..Default::default()
    });
    let key_arg = key.to_string_lossy().into_owned();
    let out = openssh(
        &go_bin,
        addr,
        &[
            "-i",
            &key_arg,
            "-o",
            "IdentitiesOnly yes",
            "tc",
            "echo key-ok",
        ],
        None,
    )
    .await;
    assert_eq!(stdout(&out), "key-ok\n");
    let out = openssh(
        &go_bin,
        addr,
        &["-o", "PubkeyAuthentication no", "tc", "echo should-fail"],
        None,
    )
    .await;
    assert!(!out.status.success());
    assert!(stdout(&out).is_empty());

    // An SSH forced command.
    set_ssh(SshOptions {
        shell: true,
        exec: vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo \"forced [$SSH_ORIGINAL_COMMAND]\"".into(),
        ],
        ..Default::default()
    });
    let out = go(&go_bin, &["ssh", addr, "rm -rf /"], None).await;
    assert_eq!(stdout(&out), "forced [rm -rf /]\n");

    // The exec service.
    let out = go(&go_bin, &[addr, &EXEC_PORT.to_string()], Some(b"shout\n")).await;
    assert!(out.status.success());
    let text = stdout(&out);
    let (env_line, echoed) = text.split_once('\n').unwrap();
    assert!(env_line.starts_with("nodekey:"), "{text}");
    assert!(env_line.ends_with(&format!(":{EXEC_PORT}")), "{text}");
    assert_eq!(echoed, "SHOUT\n");

    // tailcat cp and ls against every file service mode.
    let local = tmp.path().join("local");
    std::fs::create_dir(&local).unwrap();
    let upload = local.join("upload.txt");
    std::fs::write(&upload, "uploaded").unwrap();
    std::fs::create_dir(local.join("tree")).unwrap();
    std::fs::write(local.join("tree/leaf.txt"), "leaf").unwrap();
    let upload_arg = upload.to_string_lossy().into_owned();
    let tree_arg = local.join("tree").to_string_lossy().into_owned();
    for mode in [
        FileServeMode::ReadOnly,
        FileServeMode::ReadWrite,
        FileServeMode::WriteOnly,
        FileServeMode::WriteOnlyPlus,
    ] {
        eprintln!("# file service mode {mode:?}");
        let shared = tempfile::tempdir().unwrap();
        std::fs::write(shared.path().join("existing.txt"), "existing").unwrap();
        std::fs::create_dir(shared.path().join("sub")).unwrap();
        set_ssh(SshOptions {
            files: Some(FileService {
                dir: shared.path().into(),
                mode,
            }),
            ..Default::default()
        });
        let readable = matches!(mode, FileServeMode::ReadOnly | FileServeMode::ReadWrite);
        let writable = mode != FileServeMode::ReadOnly;

        let out = go(&go_bin, &["ls", addr], None).await;
        assert_eq!(out.status.success(), readable);
        if readable {
            assert_eq!(stdout(&out), "existing.txt\nsub/\n");
        }

        let fetched = local.join(format!("fetched-{mode:?}.txt"));
        let fetched_arg = fetched.to_string_lossy().into_owned();
        let out = go(
            &go_bin,
            &["cp", &format!("{addr}:existing.txt"), &fetched_arg],
            None,
        )
        .await;
        assert_eq!(out.status.success(), readable);
        if readable {
            assert_eq!(std::fs::read_to_string(&fetched).unwrap(), "existing");
        }

        let out = go(&go_bin, &["cp", &upload_arg, &format!("{addr}:")], None).await;
        assert_eq!(out.status.success(), writable);
        let names: Vec<String> = std::fs::read_dir(shared.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        match mode {
            FileServeMode::ReadOnly => assert!(!names.iter().any(|n| n.starts_with("upload"))),
            FileServeMode::ReadWrite | FileServeMode::WriteOnlyPlus => {
                assert_eq!(
                    std::fs::read_to_string(shared.path().join("upload.txt")).unwrap(),
                    "uploaded"
                );
            }
            FileServeMode::WriteOnly => {
                assert!(!names.contains(&"upload.txt".to_string()));
                let stored = names
                    .iter()
                    .find(|n| {
                        n.starts_with("upload.") && Path::new(n).extension() == Some("txt".as_ref())
                    })
                    .expect("server-named upload");
                assert_eq!(
                    std::fs::read_to_string(shared.path().join(stored)).unwrap(),
                    "uploaded"
                );
            }
        }

        let out = go(&go_bin, &["cp", "-r", &tree_arg, &format!("{addr}:")], None).await;
        let recursive = matches!(
            mode,
            FileServeMode::ReadWrite | FileServeMode::WriteOnlyPlus
        );
        assert_eq!(out.status.success(), recursive);
        if recursive {
            assert_eq!(
                std::fs::read_to_string(shared.path().join("tree/leaf.txt")).unwrap(),
                "leaf"
            );
        }
    }
    // tailcat perf over TCP and UDP, in each direction.
    for flags in [
        &["--parallel=2"][..],
        &["--reverse"],
        &["--bidir"],
        &["--udp", "--bitrate=20M"],
        &["--udp", "--bitrate=20M", "--reverse"],
        &["--udp", "--bitrate=20M", "--bidir"],
    ] {
        let mut args = vec!["--json", "perf", "--via-derp", "--time=2s", "--interval=0"];
        args.extend_from_slice(flags);
        args.push(addr);
        let out = go(&go_bin, &args, None).await;
        assert!(out.status.success(), "perf {flags:?} failed");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let upload = !flags.contains(&"--reverse");
        let download = flags.contains(&"--reverse") || flags.contains(&"--bidir");
        if upload {
            assert!(json_bytes(&v, "clientSent") > 0 && json_bytes(&v, "serverReceived") > 0);
        }
        if download {
            assert!(json_bytes(&v, "serverSent") > 0 && json_bytes(&v, "clientReceived") > 0);
        }
        eprintln!("  path: {}", v["path"]);
    }

    server.close();
}
