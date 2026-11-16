use std::ffi::OsString;
use std::io;
use std::process::Stdio;
use std::vec::Vec;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;

use super::Peer;

/// Runs a command for each connection, inetd-style.
///
/// The connection is the command's standard input and output, and its
/// standard error is the server's. The command's environment is the
/// server's plus [`Peer::env`]. Each direction is half-closed on its own:
/// the command reads EOF once the client shuts down its sending side, and
/// the client sees a FIN once the command closes its standard output.
#[derive(Clone, Debug)]
pub struct ExecHandler {
    argv: Vec<OsString>,
}

impl ExecHandler {
    /// # Panics
    ///
    /// Panics if `argv` is empty.
    pub fn new<I, S>(argv: I) -> ExecHandler
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let argv: Vec<OsString> = argv.into_iter().map(Into::into).collect();
        assert!(!argv.is_empty(), "ExecHandler needs a command");
        ExecHandler { argv }
    }

    /// Serves one connection and returns once the command has exited.
    ///
    /// # Errors
    ///
    /// Fails if the command cannot be started or exits unsuccessfully.
    pub async fn serve<S>(&self, stream: S, peer: &Peer) -> io::Result<()>
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let mut child = Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .envs(peer.env())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;
        let mut stdin = child.stdin.take().ok_or(io::ErrorKind::BrokenPipe)?;
        let mut stdout = child.stdout.take().ok_or(io::ErrorKind::BrokenPipe)?;
        let (mut rx, mut tx) = tokio::io::split(stream);
        let input = async move {
            let _ = tokio::io::copy(&mut rx, &mut stdin).await;
            let _ = stdin.shutdown().await;
        };
        let output = async move {
            let _ = tokio::io::copy(&mut stdout, &mut tx).await;
            let _ = tx.shutdown().await;
            tx
        };
        let ((), _tx) = tokio::join!(input, output);
        let status = child.wait().await?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(std::format!(
                "{} exited: {status}",
                self.argv[0].to_string_lossy()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::string::{String, ToString};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::key::NodePrivate;

    fn peer() -> Peer {
        Peer {
            local: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 7, 0, 0).into(),
            remote: SocketAddrV6::new("fd7a:115c:a1e0::1".parse().unwrap(), 4242, 0, 0).into(),
            key: Some(NodePrivate::generate().public()),
        }
    }

    #[test]
    fn peer_env_names_and_values() {
        let p = peer();
        let env = p.env();
        assert_eq!(
            env[0],
            (
                "TAILCAT_REMOTE_ADDR".into(),
                "[fd7a:115c:a1e0::1]:4242".into()
            )
        );
        assert_eq!(env[1], ("TAILCAT_LOCAL_ADDR".into(), "[::1]:7".into()));
        assert_eq!(env[2].0, "TAILCAT_PEER_KEY");
        assert!(env[2].1.starts_with("nodekey:"));
        let anonymous = Peer { key: None, ..p };
        assert_eq!(anonymous.env().len(), 2);
    }

    #[tokio::test]
    async fn exec_pipes_and_sees_peer_env() {
        let p = peer();
        let (mut client, server) = tokio::io::duplex(1 << 16);
        let handler = ExecHandler::new([
            "/bin/sh",
            "-c",
            "printf '%s %s %s\\n' \"$TAILCAT_REMOTE_ADDR\" \"$TAILCAT_LOCAL_ADDR\" \"$TAILCAT_PEER_KEY\"; cat",
        ]);
        let task = tokio::spawn(async move { handler.serve(server, &p).await });
        client.write_all(b"echoed").await.unwrap();
        client.shutdown().await.unwrap();
        let mut out = String::new();
        client.read_to_string(&mut out).await.unwrap();
        task.await.unwrap().unwrap();
        let key = p.key.unwrap();
        assert_eq!(
            out,
            std::format!("[fd7a:115c:a1e0::1]:4242 [::1]:7 {key}\nechoed")
        );
    }

    #[tokio::test]
    async fn exec_reports_failure() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let err = ExecHandler::new(["/bin/sh", "-c", "exit 3"])
            .serve(server, &peer())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("exited"));
    }
}
