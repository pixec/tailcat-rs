use std::net::{Ipv6Addr, SocketAddrV6};
use std::time::Duration;

use russh::client;
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key::LineEnding;

use super::*;
use crate::key::NodePrivate;

struct AcceptAny;

impl client::Handler for AcceptAny {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _: &russh::keys::PublicKeyOrCertificate,
    ) -> core::result::Result<bool, russh::Error> {
        Ok(true)
    }
}

fn new_key() -> PrivateKey {
    PrivateKey::new(
        KeypairData::Ed25519(Ed25519Keypair::from_seed(&rand::random())),
        "test",
    )
    .unwrap()
}

fn authorized_line(key: &PrivateKey) -> String {
    key.public_key().to_openssh().unwrap()
}

fn peer() -> Peer {
    Peer {
        local: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 22, 0, 0).into(),
        remote: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 40000, 0, 0).into(),
        key: Some(NodePrivate::generate().public()),
    }
}

struct Env {
    handler: SshHandler,
    peer: Peer,
    _dir: tempfile::TempDir,
}

fn env(mut opts: SshOptions) -> Env {
    let dir = tempfile::tempdir().unwrap();
    opts.host_key = Some(dir.path().join("host_key"));
    Env {
        handler: SshHandler::new(opts).unwrap(),
        peer: peer(),
        _dir: dir,
    }
}

fn shell() -> Env {
    env(SshOptions {
        shell: true,
        ..Default::default()
    })
}

impl Env {
    async fn connect(&self) -> client::Handle<AcceptAny> {
        let (a, b) = tokio::io::duplex(1 << 20);
        let handler = self.handler.clone();
        let peer = self.peer;
        tokio::spawn(async move { handler.serve(a, peer).await });
        client::connect_stream(Arc::new(client::Config::default()), b, AcceptAny)
            .await
            .unwrap()
    }

    async fn client(&self) -> client::Handle<AcceptAny> {
        let mut c = self.connect().await;
        assert!(c.authenticate_none("test").await.unwrap().success());
        c
    }
}

#[derive(Default, Debug)]
struct Output {
    stdout: String,
    stderr: String,
    status: Option<u32>,
}

async fn collect(mut ch: Channel<client::Msg>) -> Output {
    let mut out = Output::default();
    let wait = async {
        while let Some(msg) = ch.wait().await {
            match msg {
                ChannelMsg::Data { data } => out.stdout.push_str(&String::from_utf8_lossy(&data)),
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    out.stderr.push_str(&String::from_utf8_lossy(&data));
                }
                ChannelMsg::ExitStatus { exit_status } => out.status = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(20), wait)
        .await
        .expect("session timed out");
    out
}

async fn run(c: &client::Handle<AcceptAny>, env: &[(&str, &str)], cmd: &str) -> Output {
    let ch = c.channel_open_session().await.unwrap();
    for (k, v) in env {
        ch.set_env(true, *k, *v).await.unwrap();
    }
    ch.exec(true, cmd).await.unwrap();
    ch.eof().await.unwrap();
    collect(ch).await
}

async fn pty_shell(c: &client::Handle<AcceptAny>, input: &str, modes: &[(Pty, u32)]) -> Output {
    let ch = c.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, modes)
        .await
        .unwrap();
    ch.request_shell(true).await.unwrap();
    ch.data(input.as_bytes()).await.unwrap();
    collect(ch).await
}

#[test]
fn validate_authorized_keys() {
    let line = authorized_line(&new_key());
    let cases: [(&str, Vec<String>, &str); 5] = [
        ("one key", std::vec![line.clone()], ""),
        (
            "multiple entries",
            std::vec![
                "# comment only".into(),
                line.clone(),
                std::format!("\n{line}\n")
            ],
            "",
        ),
        (
            "no keys",
            std::vec!["\n# only a comment\n".into()],
            "no SSH public keys",
        ),
        (
            "malformed",
            std::vec!["ssh-ed25519 not-base64".into()],
            "line 1",
        ),
        (
            "options",
            std::vec![std::format!("command=\"echo no\" {line}")],
            "options are not supported",
        ),
    ];
    for (name, texts, want) in cases {
        let got = validate_ssh_authorized_keys(&texts);
        if want.is_empty() {
            assert!(got.is_ok(), "{name}: {got:?}");
        } else {
            let err = got.expect_err(name).to_string();
            assert!(err.contains(want), "{name}: {err}");
        }
    }
    assert!(validate_ssh_authorized_keys::<String>(&[]).is_err());
}

#[test]
fn host_key_is_generated_once_as_pkcs8() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key");
    let first = load_host_key(Some(path.clone())).unwrap();
    assert!(
        std::fs::read_to_string(&path)
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
    let second = load_host_key(Some(path)).unwrap();
    assert_eq!(
        first.public_key().key_data(),
        second.public_key().key_data()
    );
    assert!(first.to_openssh(LineEnding::LF).is_ok());
}

#[tokio::test]
async fn public_key_authentication() {
    let authorized = new_key();
    let unauthorized = new_key();
    let env = env(SshOptions {
        shell: true,
        authorized_keys: Some(std::vec![std::format!(
            "# trusted\n{}\n",
            authorized_line(&authorized)
        )]),
        ..Default::default()
    });
    let key = |k: &PrivateKey| PrivateKeyWithHashAlg::new(Arc::new(k.clone()), None);

    let mut c = env.connect().await;
    assert!(!c.authenticate_none("test").await.unwrap().success());
    assert!(
        !c.authenticate_publickey("test", key(&unauthorized))
            .await
            .unwrap()
            .success()
    );
    assert!(
        c.authenticate_publickey("test", key(&authorized))
            .await
            .unwrap()
            .success()
    );

    let out = run(&c, &[], "echo authenticated").await;
    assert_eq!(out.stdout.trim(), "authenticated");
    let out = pty_shell(
        &c,
        "echo authenticated-interactive\nexit\n",
        &[(Pty::ECHO, 0)],
    )
    .await;
    assert!(out.stdout.contains("authenticated-interactive"), "{out:?}");
    assert!(out.stdout.contains("Connected via tailcat SSH."), "{out:?}");
}

#[tokio::test]
async fn interactive_motd_requires_pty() {
    let env = shell();
    let c = env.client().await;
    let ch = c.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    ch.data(&b"echo no-pty\nexit\n"[..]).await.unwrap();
    let out = collect(ch).await;
    assert!(out.stdout.contains("no-pty"), "{out:?}");
    assert!(
        !out.stdout.contains("Connected via tailcat SSH."),
        "{out:?}"
    );

    let out = pty_shell(&c, "exit\n", &[]).await;
    assert!(out.stdout.contains("Connected via tailcat SSH."), "{out:?}");
    let ch = c.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.exec(true, "echo with-command").await.unwrap();
    let out = collect(ch).await;
    assert!(out.stdout.contains("with-command"), "{out:?}");
    assert!(
        !out.stdout.contains("Connected via tailcat SSH."),
        "{out:?}"
    );
}

#[tokio::test]
async fn suite() {
    let env = shell();
    let c = env.client().await;

    let out = run(&c, &[], "echo hello").await;
    assert_eq!((out.stdout.as_str(), out.status), ("hello\n", Some(0)));

    let out = run(&c, &[], "exit 42").await;
    assert_eq!(out.status, Some(42));

    let out = run(&c, &[], "echo out; echo err >&2").await;
    assert_eq!(
        (out.stdout.as_str(), out.stderr.as_str()),
        ("out\n", "err\n")
    );

    let out = run(
        &c,
        &[
            ("LANG", "en_US.UTF-8"),
            ("LC_TEST", "x"),
            ("FOO", "rejected"),
        ],
        "echo \"$LANG|$LC_TEST|$FOO\"",
    )
    .await;
    assert_eq!(out.stdout, "en_US.UTF-8|x|\n");

    let out = run(&c, &[], "echo \"$TAILCAT_PEER_KEY|$TAILCAT_REMOTE_ADDR\"").await;
    assert_eq!(out.stdout, std::format!("{}|\n", env.peer.key.unwrap()));

    let out = run(&c, &[], "cat").await;
    assert_eq!(out.stdout, "");

    let ch = c.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
        .await
        .unwrap();
    ch.exec(true, "test -t 0 && echo \"tty $TERM $(stty size)\"")
        .await
        .unwrap();
    let out = collect(ch).await;
    assert_eq!(out.stdout.trim(), "tty xterm-256color 30 100");

    let ch = c.channel_open_session().await.unwrap();
    ch.exec(true, "test -t 0 || echo no-tty").await.unwrap();
    ch.eof().await.unwrap();
    assert_eq!(collect(ch).await.stdout, "no-tty\n");

    let mut ch = c.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.exec(
        true,
        "trap 'echo got-int; exit 7' INT; echo ready; while :; do sleep 0.1; done",
    )
    .await
    .unwrap();
    let mut seen = String::new();
    while !seen.contains("ready") {
        if let Some(ChannelMsg::Data { data }) = ch.wait().await {
            seen.push_str(&String::from_utf8_lossy(&data));
        }
    }
    ch.data(&b"\x03"[..]).await.unwrap();
    let out = collect(ch).await;
    assert!(out.stdout.contains("got-int"), "{out:?}");
    assert_eq!(out.status, Some(7));

    let ch = c.channel_open_session().await.unwrap();
    ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
        .await
        .unwrap();
    ch.exec(true, "sleep 0.5; stty size").await.unwrap();
    ch.window_change(132, 50, 0, 0).await.unwrap();
    assert_eq!(collect(ch).await.stdout.trim(), "50 132");

    let mut ch = c.channel_open_session().await.unwrap();
    ch.exec(
        true,
        "trap 'exit 9' TERM; echo ready; while :; do sleep 0.1; done",
    )
    .await
    .unwrap();
    let mut seen = String::new();
    while !seen.contains("ready") {
        if let Some(ChannelMsg::Data { data }) = ch.wait().await {
            seen.push_str(&String::from_utf8_lossy(&data));
        }
    }
    ch.signal(Sig::TERM).await.unwrap();
    assert_eq!(collect(ch).await.status, Some(9));
}

#[tokio::test]
async fn forced_command() {
    let env = env(SshOptions {
        shell: true,
        exec: std::vec![
            "/bin/sh".into(),
            "-c".into(),
            "echo \"[$SSH_ORIGINAL_COMMAND] $TAILCAT_REMOTE_ADDR $TAILCAT_PEER_KEY\"".into(),
        ],
        #[cfg(feature = "sftp")]
        files: Some(FileService {
            dir: "/".into(),
            mode: sftp::FileServeMode::ReadOnly,
        }),
        ..Default::default()
    });
    let c = env.client().await;
    let out = run(&c, &[], "ignored command").await;
    assert_eq!(
        out.stdout,
        std::format!(
            "[ignored command] {} {}\n",
            env.peer.remote,
            env.peer.key.unwrap()
        )
    );
    let ch = c.channel_open_session().await.unwrap();
    ch.request_shell(true).await.unwrap();
    ch.eof().await.unwrap();
    assert!(collect(ch).await.stdout.starts_with("[] "));

    let mut ch = c.channel_open_session().await.unwrap();
    assert!(ch.request_subsystem(true, "sftp").await.is_ok());
    assert!(matches!(ch.wait().await, Some(ChannelMsg::Failure)));
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn files_only() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("hello.txt"), "hi").unwrap();
    let env = env(SshOptions {
        files: Some(FileService {
            dir: dir.path().into(),
            mode: sftp::FileServeMode::ReadOnly,
        }),
        ..Default::default()
    });
    let c = env.client().await;
    let out = run(&c, &[], "echo nope").await;
    assert_eq!(out.status, Some(1));
    assert_eq!(out.stderr, FILES_ONLY);
    assert_eq!(out.stdout, "");

    let ch = c.channel_open_session().await.unwrap();
    ch.request_subsystem(true, "sftp").await.unwrap();
    let sftp = russh_sftp::client::SftpSession::new(ch.into_stream())
        .await
        .unwrap();
    let names: Vec<String> = sftp
        .read_dir(".")
        .await
        .unwrap()
        .map(|e| e.file_name())
        .collect();
    assert_eq!(names, ["hello.txt"]);
    assert_eq!(sftp.read("hello.txt").await.unwrap(), b"hi");
}

#[cfg(feature = "sftp")]
#[tokio::test]
async fn full_sftp_with_shell() {
    let env = shell();
    let c = env.client().await;
    let ch = c.channel_open_session().await.unwrap();
    ch.request_subsystem(true, "sftp").await.unwrap();
    let sftp = russh_sftp::client::SftpSession::new(ch.into_stream())
        .await
        .unwrap();
    let home = std::env::home_dir().unwrap();
    assert_eq!(
        sftp.canonicalize(".").await.unwrap(),
        home.to_string_lossy()
    );
    let tmp = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("/etc", tmp.path().join("etc")).unwrap();
    let p = tmp.path().join("etc").to_string_lossy().into_owned();
    assert!(sftp.metadata(p).await.unwrap().is_dir());
}
