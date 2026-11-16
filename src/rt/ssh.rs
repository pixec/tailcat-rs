use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use std::string::{String, ToString};
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use nix::sys::signal::{Signal, kill};
use nix::sys::termios::{
    ControlFlags, InputFlags, LocalFlags, OutputFlags, SetArg, SpecialCharacterIndices, Termios,
    tcgetattr, tcsetattr,
};
use nix::unistd::{Pid, Uid, User};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{PrivateKey, PublicKey};
use russh::server::{Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session, VerifiedPublicKey};
use russh::{
    Channel, ChannelId, ChannelMsg, ChannelReadHalf, ChannelWriteHalf, MethodKind, Pty, Sig,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};

use super::Peer;
#[cfg(feature = "sftp")]
use super::sftp::{self, FileService, Files};
use crate::error::{AuthorizedKeysError, Error, Result};

const MOTD: &str = "\u{1f408} Connected via tailcat SSH.\r\n";
const FILES_ONLY: &str = "this tailcat server only offers file transfer (SFTP); shell and exec sessions are disabled\r\n";
const HOST_KEY_FILE: &str = "ssh_host_ed25519_key";

nix::ioctl_write_ptr_bad!(tiocswinsz, nix::libc::TIOCSWINSZ, nix::pty::Winsize);
nix::ioctl_write_int_bad!(tiocsctty, nix::libc::TIOCSCTTY);

/// What an [`SshHandler`] offers.
#[derive(Clone, Debug, Default)]
pub struct SshOptions {
    /// Enables shell and exec sessions: a client's command runs in the
    /// user's shell, and without one an interactive login shell starts.
    pub shell: bool,
    /// A command every session runs instead of a shell or the client's
    /// command, like OpenSSH's `ForceCommand`. When non-empty, `shell` and
    /// `files` are ignored and nothing else is offered. The client's
    /// command, if any, is passed in `SSH_ORIGINAL_COMMAND`, and the peer is
    /// described by [`Peer::env`].
    pub exec: Vec<String>,
    /// OpenSSH `authorized_keys` text, each element holding any number of
    /// key lines. Clients must authenticate with a listed key. `None` relies
    /// on the tunnel for client identity. Key options are rejected, since
    /// their restrictions are not implemented.
    pub authorized_keys: Option<Vec<String>>,
    /// Serves the SFTP subsystem rooted at this directory. Without it, a
    /// server with `shell` serves SFTP over the whole filesystem with
    /// relative paths resolved against the home directory.
    #[cfg(feature = "sftp")]
    pub files: Option<FileService>,
    /// Where the ed25519 host key is kept, generated on first use. `None`
    /// means `tailcat/ssh/ssh_host_ed25519_key` under the user's
    /// configuration directory, shared with the Go server.
    pub host_key: Option<PathBuf>,
}

enum Sessions {
    Shell,
    Exec(Vec<String>),
    FilesOnly,
}

struct Policy {
    sessions: Sessions,
    #[cfg(feature = "sftp")]
    files: Option<FileService>,
    sftp: bool,
    authorized: Option<Vec<KeyData>>,
}

impl Policy {
    fn allows(&self, key: &PublicKey) -> Auth {
        match &self.authorized {
            Some(keys) if keys.contains(key.key_data()) => Auth::Accept,
            _ => Auth::reject(),
        }
    }
}

/// Serves SSH sessions on accepted connections, usually those to port 22.
///
/// Clients authenticate by a listed public key, or not at all when the
/// tunnel's identity suffices. Sessions run a shell, a client command or a
/// forced command, with a PTY if requested, and the `sftp` subsystem is
/// served as configured in [`SshOptions`].
#[derive(Clone)]
pub struct SshHandler {
    config: Arc<russh::server::Config>,
    policy: Arc<Policy>,
}

/// Checks that `texts` hold at least one public key and nothing but blank
/// lines, comments and key lines in OpenSSH `authorized_keys` format.
///
/// # Errors
///
/// Returns the first offending entry and line, or
/// [`AuthorizedKeysError::Empty`] if there are no keys.
pub fn validate_ssh_authorized_keys<S: AsRef<str>>(
    texts: &[S],
) -> core::result::Result<(), AuthorizedKeysError> {
    parse_authorized_keys(texts).map(drop)
}

fn parse_authorized_keys<S: AsRef<str>>(
    texts: &[S],
) -> core::result::Result<Vec<KeyData>, AuthorizedKeysError> {
    let mut keys = Vec::new();
    for (entry, text) in texts.iter().enumerate() {
        for (line_index, line) in text.as_ref().split('\n').enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (entry, line_no) = (entry + 1, line_index + 1);
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let key_at = |i: usize| {
                tokens
                    .get(i..i + 2)
                    .and_then(|t| PublicKey::from_openssh(&t.join(" ")).ok())
            };
            if let Some(key) = key_at(0) {
                keys.push(key.key_data().clone());
            } else if (1..tokens.len()).any(|i| key_at(i).is_some()) {
                return Err(AuthorizedKeysError::Options {
                    entry,
                    line: line_no,
                });
            } else {
                return Err(AuthorizedKeysError::NoKey {
                    entry,
                    line: line_no,
                });
            }
        }
    }
    if keys.is_empty() {
        return Err(AuthorizedKeysError::Empty);
    }
    Ok(keys)
}

fn user_config_dir() -> Option<PathBuf> {
    if cfg!(target_vendor = "apple") {
        return std::env::home_dir().map(|h| h.join("Library/Application Support"));
    }
    match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) if Path::new(&dir).is_absolute() => Some(dir.into()),
        _ => std::env::home_dir().map(|h| h.join(".config")),
    }
}

fn load_host_key(path: Option<PathBuf>) -> Result<PrivateKey> {
    static GENERATING: Mutex<()> = Mutex::new(());
    let path = if let Some(p) = path {
        p
    } else {
        let dir = user_config_dir()
            .ok_or_else(|| io::Error::other("no user configuration directory"))?
            .join("tailcat/ssh");
        DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        dir.join(HOST_KEY_FILE)
    };
    let _guard = GENERATING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pem = match std::fs::read_to_string(&path) {
        Ok(pem) => pem,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = PrivateKey::new(
                KeypairData::Ed25519(Ed25519Keypair::from_seed(&rand::random())),
                "",
            )
            .map_err(|e| Error::HostKey {
                path: path.clone(),
                source: e.into(),
            })?;
            let mut pem = Vec::new();
            russh::keys::encode_pkcs8_pem(&key, &mut pem).map_err(|source| Error::HostKey {
                path: path.clone(),
                source,
            })?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
                .write_all(&pem)?;
            return Ok(key);
        }
        Err(e) => return Err(e.into()),
    };
    russh::keys::decode_secret_key(&pem, None).map_err(|source| Error::HostKey { path, source })
}

impl SshHandler {
    /// Validates the options and loads, or generates, the host key.
    ///
    /// # Errors
    ///
    /// Fails if the authorized keys are invalid or the host key cannot be
    /// read, parsed or created.
    pub fn new(opts: SshOptions) -> Result<SshHandler> {
        let authorized = opts
            .authorized_keys
            .as_deref()
            .map(parse_authorized_keys)
            .transpose()?;
        let sessions = if !opts.exec.is_empty() {
            Sessions::Exec(opts.exec)
        } else if opts.shell {
            Sessions::Shell
        } else {
            Sessions::FilesOnly
        };
        #[cfg(feature = "sftp")]
        let files = opts
            .files
            .filter(|_| !matches!(sessions, Sessions::Exec(_)));
        #[cfg(feature = "sftp")]
        let sftp = files.is_some() || matches!(sessions, Sessions::Shell);
        #[cfg(not(feature = "sftp"))]
        let sftp = false;
        let methods = if authorized.is_some() {
            MethodKind::PublicKey
        } else {
            MethodKind::None
        };
        let config = russh::server::Config {
            keys: std::vec![load_host_key(opts.host_key)?],
            methods: (&[methods][..]).into(),
            auth_rejection_time_initial: Some(core::time::Duration::ZERO),
            inactivity_timeout: None,
            ..Default::default()
        };
        Ok(SshHandler {
            config: Arc::new(config),
            policy: Arc::new(Policy {
                sessions,
                #[cfg(feature = "sftp")]
                files,
                sftp,
                authorized,
            }),
        })
    }

    /// Serves one connection until the client disconnects.
    ///
    /// # Errors
    ///
    /// Returns the SSH protocol error that ended the connection, if any.
    pub async fn serve<S>(&self, stream: S, peer: Peer) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let conn = Connection {
            policy: self.policy.clone(),
            peer,
        };
        russh::server::run_stream(self.config.clone(), stream, conn)
            .await?
            .await?;
        Ok(())
    }
}

struct Connection {
    policy: Arc<Policy>,
    peer: Peer,
}

fn accept_env(name: &str) -> bool {
    name == "TERM" || name == "LANG" || name.starts_with("LC_")
}

impl russh::server::Handler for Connection {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> core::result::Result<Auth, russh::Error> {
        Ok(if self.policy.authorized.is_none() {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        _user: &str,
        offer: PublicKeyOffer<'_>,
    ) -> core::result::Result<Auth, russh::Error> {
        Ok(self.policy.allows(offer.public_key))
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        key: VerifiedPublicKey<'_>,
    ) -> core::result::Result<Auth, russh::Error> {
        Ok(self.policy.allows(key.public_key))
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> core::result::Result<(), russh::Error> {
        reply.accept().await;
        tokio::spawn(run_channel(channel, self.policy.clone(), self.peer));
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> core::result::Result<(), russh::Error> {
        session.channel_success(channel)
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> core::result::Result<(), russh::Error> {
        session.channel_success(channel)
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> core::result::Result<(), russh::Error> {
        session.channel_success(channel)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _command: &[u8],
        session: &mut Session,
    ) -> core::result::Result<(), russh::Error> {
        session.channel_success(channel)
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> core::result::Result<(), russh::Error> {
        if name == "sftp" && self.policy.sftp {
            session.channel_success(channel)
        } else {
            session.channel_failure(channel)
        }
    }
}

struct PtyRequest {
    term: String,
    size: nix::pty::Winsize,
    modes: Vec<(Pty, u32)>,
}

enum Start {
    Command(String),
    #[cfg(feature = "sftp")]
    Sftp,
}

fn winsize(cols: u32, rows: u32, pix_width: u32, pix_height: u32) -> nix::pty::Winsize {
    let clamp = |v: u32| u16::try_from(v).unwrap_or(u16::MAX);
    nix::pty::Winsize {
        ws_row: clamp(rows),
        ws_col: clamp(cols),
        ws_xpixel: clamp(pix_width),
        ws_ypixel: clamp(pix_height),
    }
}

async fn run_channel(mut channel: Channel<Msg>, policy: Arc<Policy>, peer: Peer) {
    let mut env = Vec::new();
    let mut pty = None;
    let start = loop {
        match channel.wait().await {
            Some(ChannelMsg::RequestPty {
                term,
                col_width,
                row_height,
                pix_width,
                pix_height,
                terminal_modes,
                ..
            }) => {
                pty = Some(PtyRequest {
                    term,
                    size: winsize(col_width, row_height, pix_width, pix_height),
                    modes: terminal_modes,
                });
            }
            Some(ChannelMsg::SetEnv {
                variable_name,
                variable_value,
                ..
            }) if accept_env(&variable_name) => env.push((variable_name, variable_value)),
            Some(ChannelMsg::RequestShell { .. }) => break Start::Command(String::new()),
            Some(ChannelMsg::Exec { command, .. }) => {
                break Start::Command(String::from_utf8_lossy(&command).into_owned());
            }
            #[cfg(feature = "sftp")]
            Some(ChannelMsg::RequestSubsystem { name, .. }) if name == "sftp" && policy.sftp => {
                break Start::Sftp;
            }
            Some(ChannelMsg::Eof | ChannelMsg::Close) | None => return,
            Some(_) => {}
        }
    };
    let (read, write) = channel.split();
    #[cfg(feature = "sftp")]
    let Start::Command(raw) = start else {
        return serve_sftp(read, write, policy.files.as_ref()).await;
    };
    #[cfg(not(feature = "sftp"))]
    let Start::Command(raw) = start;
    let mut cmd = match &policy.sessions {
        Sessions::FilesOnly => return fail(&write, FILES_ONLY).await,
        Sessions::Shell => match shell_command(&raw, &peer).await {
            Ok(cmd) => cmd,
            Err(msg) => return fail(&write, &msg).await,
        },
        Sessions::Exec(argv) => {
            let mut cmd = Command::new(&argv[0]);
            cmd.args(&argv[1..]).envs(peer.env());
            cmd
        }
    };
    cmd.envs(env);
    if let Sessions::Exec(_) = policy.sessions
        && !raw.is_empty()
    {
        cmd.env("SSH_ORIGINAL_COMMAND", &raw);
    }
    let motd = pty.is_some() && raw.is_empty() && matches!(policy.sessions, Sessions::Shell);
    let code = match pty {
        Some(pty) => run_with_pty(read, &write, cmd, &pty, motd).await,
        None => run_with_pipes(read, &write, cmd).await,
    };
    match code {
        Ok(code) => finish(&write, code).await,
        Err(msg) => fail(&write, &msg).await,
    }
}

async fn finish(write: &ChannelWriteHalf<Msg>, code: u32) {
    let _ = write.eof().await;
    let _ = write.exit_status(code).await;
    let _ = write.close().await;
}

async fn fail(write: &ChannelWriteHalf<Msg>, msg: &str) {
    let mut stderr = write.make_writer_ext(Some(1));
    let _ = stderr.write_all(msg.as_bytes()).await;
    let _ = stderr.flush().await;
    finish(write, 1).await;
}

async fn login_shell(user: &User) -> String {
    if cfg!(target_vendor = "apple") {
        let out = Command::new("dscl")
            .args([".", "-read"])
            .arg(Path::new("/Users").join(&user.name))
            .arg("UserShell")
            .output()
            .await;
        if let Ok(out) = out
            && let Some(shell) = String::from_utf8_lossy(&out.stdout).strip_prefix("UserShell: ")
        {
            return shell.trim().into();
        }
    }
    match std::env::var("SHELL") {
        Ok(shell) if !shell.is_empty() => shell,
        _ => "/bin/sh".into(),
    }
}

async fn shell_command(raw: &str, peer: &Peer) -> core::result::Result<Command, String> {
    let user = match User::from_uid(Uid::current()) {
        Ok(Some(user)) => user,
        Ok(None) => return Err("failed to get current user: unknown uid\r\n".into()),
        Err(e) => return Err(std::format!("failed to get current user: {e}\r\n")),
    };
    let shell = login_shell(&user).await;
    let mut cmd = Command::new(&shell);
    if raw.is_empty() {
        cmd.arg("-l");
    } else {
        cmd.args(["-c", raw]);
    }
    let path = if user.uid.is_root() {
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    } else {
        "/usr/local/bin:/usr/bin:/bin"
    };
    cmd.current_dir(&user.dir)
        .env_clear()
        .env("SHELL", &shell)
        .env("USER", &user.name)
        .env("HOME", &user.dir)
        .env("PATH", path);
    if let Some(key) = peer.key {
        cmd.env("TAILCAT_PEER_KEY", key.to_string());
    }
    Ok(cmd)
}

fn exit_code(status: std::process::ExitStatus) -> u32 {
    status.code().map_or(u32::MAX, i32::cast_unsigned)
}

fn to_signal(sig: &Sig) -> Option<Signal> {
    Some(match sig {
        Sig::ABRT => Signal::SIGABRT,
        Sig::ALRM => Signal::SIGALRM,
        Sig::FPE => Signal::SIGFPE,
        Sig::HUP => Signal::SIGHUP,
        Sig::ILL => Signal::SIGILL,
        Sig::INT => Signal::SIGINT,
        Sig::KILL => Signal::SIGKILL,
        Sig::PIPE => Signal::SIGPIPE,
        Sig::QUIT => Signal::SIGQUIT,
        Sig::SEGV => Signal::SIGSEGV,
        Sig::TERM => Signal::SIGTERM,
        Sig::USR1 => Signal::SIGUSR1,
        Sig::Custom(name) => return Signal::from_str(&std::format!("SIG{name}")).ok(),
    })
}

fn signal_child(pid: Option<u32>, sig: &Sig) {
    if let (Some(pid), Some(sig)) = (pid.and_then(|p| i32::try_from(p).ok()), to_signal(sig)) {
        let _ = kill(Pid::from_raw(pid), sig);
    }
}

async fn run_with_pipes(
    mut read: ChannelReadHalf,
    write: &ChannelWriteHalf<Msg>,
    mut cmd: Command,
) -> core::result::Result<u32, String> {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| std::format!("start: {e}\r\n"))?;
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let pid = child.id();
    let input = tokio::spawn(async move {
        while let Some(msg) = read.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    if let Some(w) = stdin.as_mut()
                        && w.write_all(&data).await.is_err()
                    {
                        stdin = None;
                    }
                }
                ChannelMsg::Eof => stdin = None,
                ChannelMsg::Signal { signal } => signal_child(pid, &signal),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    });
    let mut out = write.make_writer();
    let mut err = write.make_writer_ext(Some(1));
    let _ = tokio::join!(
        async {
            let _ = tokio::io::copy(&mut stdout, &mut out).await;
            out.flush().await
        },
        async {
            let _ = tokio::io::copy(&mut stderr, &mut err).await;
            err.flush().await
        },
    );
    let code = wait(&mut child).await;
    input.abort();
    Ok(code)
}

async fn wait(child: &mut Child) -> u32 {
    child.wait().await.map_or(1, exit_code)
}

fn apply_modes(t: &mut Termios, modes: &[(Pty, u32)]) {
    use SpecialCharacterIndices as C;
    for &(op, v) in modes {
        let on = v != 0;
        let cc = match op {
            Pty::VINTR => Some(C::VINTR),
            Pty::VQUIT => Some(C::VQUIT),
            Pty::VERASE => Some(C::VERASE),
            Pty::VKILL => Some(C::VKILL),
            Pty::VEOF => Some(C::VEOF),
            Pty::VEOL => Some(C::VEOL),
            Pty::VEOL2 => Some(C::VEOL2),
            Pty::VSTART => Some(C::VSTART),
            Pty::VSTOP => Some(C::VSTOP),
            Pty::VSUSP => Some(C::VSUSP),
            Pty::VREPRINT => Some(C::VREPRINT),
            Pty::VWERASE => Some(C::VWERASE),
            Pty::VLNEXT => Some(C::VLNEXT),
            Pty::VDISCARD => Some(C::VDISCARD),
            _ => None,
        };
        if let Some(i) = cc {
            t.control_chars[i as usize] = u8::try_from(v).unwrap_or(u8::MAX);
            continue;
        }
        match op {
            Pty::IGNPAR => t.input_flags.set(InputFlags::IGNPAR, on),
            Pty::PARMRK => t.input_flags.set(InputFlags::PARMRK, on),
            Pty::INPCK => t.input_flags.set(InputFlags::INPCK, on),
            Pty::ISTRIP => t.input_flags.set(InputFlags::ISTRIP, on),
            Pty::INLCR => t.input_flags.set(InputFlags::INLCR, on),
            Pty::IGNCR => t.input_flags.set(InputFlags::IGNCR, on),
            Pty::ICRNL => t.input_flags.set(InputFlags::ICRNL, on),
            Pty::IXON => t.input_flags.set(InputFlags::IXON, on),
            Pty::IXANY => t.input_flags.set(InputFlags::IXANY, on),
            Pty::IXOFF => t.input_flags.set(InputFlags::IXOFF, on),
            Pty::IMAXBEL => t.input_flags.set(InputFlags::IMAXBEL, on),
            #[cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]
            Pty::IUTF8 => t.input_flags.set(InputFlags::IUTF8, on),
            Pty::ISIG => t.local_flags.set(LocalFlags::ISIG, on),
            Pty::ICANON => t.local_flags.set(LocalFlags::ICANON, on),
            Pty::ECHO => t.local_flags.set(LocalFlags::ECHO, on),
            Pty::ECHOE => t.local_flags.set(LocalFlags::ECHOE, on),
            Pty::ECHOK => t.local_flags.set(LocalFlags::ECHOK, on),
            Pty::ECHONL => t.local_flags.set(LocalFlags::ECHONL, on),
            Pty::NOFLSH => t.local_flags.set(LocalFlags::NOFLSH, on),
            Pty::TOSTOP => t.local_flags.set(LocalFlags::TOSTOP, on),
            Pty::IEXTEN => t.local_flags.set(LocalFlags::IEXTEN, on),
            Pty::ECHOCTL => t.local_flags.set(LocalFlags::ECHOCTL, on),
            Pty::ECHOKE => t.local_flags.set(LocalFlags::ECHOKE, on),
            Pty::PENDIN => t.local_flags.set(LocalFlags::PENDIN, on),
            Pty::OPOST => t.output_flags.set(OutputFlags::OPOST, on),
            Pty::ONLCR => t.output_flags.set(OutputFlags::ONLCR, on),
            Pty::OCRNL => t.output_flags.set(OutputFlags::OCRNL, on),
            Pty::ONOCR => t.output_flags.set(OutputFlags::ONOCR, on),
            Pty::ONLRET => t.output_flags.set(OutputFlags::ONLRET, on),
            Pty::CS7 | Pty::CS8 if on => {
                t.control_flags.remove(ControlFlags::CSIZE);
                t.control_flags.insert(if op == Pty::CS7 {
                    ControlFlags::CS7
                } else {
                    ControlFlags::CS8
                });
            }
            Pty::PARENB => t.control_flags.set(ControlFlags::PARENB, on),
            Pty::PARODD => t.control_flags.set(ControlFlags::PARODD, on),
            _ => {}
        }
    }
}

fn set_winsize(fd: &OwnedFd, size: nix::pty::Winsize) {
    unsafe {
        let _ = tiocswinsz(fd.as_raw_fd(), &raw const size);
    }
}

async fn run_with_pty(
    mut read: ChannelReadHalf,
    write: &ChannelWriteHalf<Msg>,
    mut cmd: Command,
    req: &PtyRequest,
    motd: bool,
) -> core::result::Result<u32, String> {
    let pty =
        nix::pty::openpty(Some(&req.size), None).map_err(|e| std::format!("pty open: {e}\r\n"))?;
    if let Ok(mut t) = tcgetattr(&pty.slave) {
        apply_modes(&mut t, &req.modes);
        let _ = tcsetattr(&pty.slave, SetArg::TCSANOW, &t);
    }
    if !req.term.is_empty() {
        cmd.env("TERM", &req.term);
    }
    let stdio = |fd: &OwnedFd| fd.try_clone().map(Stdio::from);
    let open = |e: io::Error| std::format!("start: {e}\r\n");
    cmd.stdin(stdio(&pty.slave).map_err(open)?)
        .stdout(stdio(&pty.slave).map_err(open)?)
        .stderr(stdio(&pty.slave).map_err(open)?);
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid()?;
            tiocsctty(0, 0)?;
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    drop(cmd);
    drop(pty.slave);
    let mut child = spawned.map_err(open)?;
    let pid = child.id();
    let master = pty.master;
    let resize = master.try_clone().map_err(open)?;
    let mut reader =
        tokio::fs::File::from_std(std::fs::File::from(master.try_clone().map_err(open)?));
    let mut writer = tokio::fs::File::from_std(std::fs::File::from(master));
    let input = tokio::spawn(async move {
        while let Some(msg) = read.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    let _ = writer.write_all(&data).await;
                    let _ = writer.flush().await;
                }
                ChannelMsg::WindowChange {
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                } => set_winsize(
                    &resize,
                    winsize(col_width, row_height, pix_width, pix_height),
                ),
                ChannelMsg::Signal { signal } => signal_child(pid, &signal),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
    });
    let mut out = write.make_writer();
    if motd {
        let _ = out.write_all(MOTD.as_bytes()).await;
    }
    let mut buf = std::vec![0; 32 << 10];
    while let Ok(n) = reader.read(&mut buf).await {
        if n == 0 || out.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = out.flush().await;
    let code = wait(&mut child).await;
    input.abort();
    Ok(code)
}

#[cfg(feature = "sftp")]
async fn serve_sftp(
    mut read: ChannelReadHalf,
    write: ChannelWriteHalf<Msg>,
    service: Option<&FileService>,
) {
    let files = match Files::open(service) {
        Ok(files) => files,
        Err(e) => {
            tracing::warn!("sftp session: {e}");
            return finish(&write, 1).await;
        }
    };
    let (ours, theirs) = tokio::io::duplex(256 << 10);
    let server = tokio::spawn(sftp::serve(theirs, files));
    let (mut from_server, mut to_server) = tokio::io::split(ours);
    let input = tokio::spawn(async move {
        while let Some(msg) = read.wait().await {
            let data = match msg {
                ChannelMsg::Data { data } => data,
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => continue,
            };
            if to_server.write_all(&data).await.is_err() {
                break;
            }
        }
        let _ = to_server.shutdown().await;
    });
    let mut out = write.make_writer();
    let _ = tokio::io::copy(&mut from_server, &mut out).await;
    let _ = out.flush().await;
    let _ = server.await;
    input.abort();
    finish(&write, 0).await;
}

#[cfg(test)]
mod tests;
