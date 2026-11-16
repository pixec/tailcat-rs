# tailcat-rs

The Rust implementation of [Tailcat](https://github.com/tailscale/tailcat)'s server component, enabling Tailcat clients to securely access local services over WireGuard and DERP.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

tailcat-rs requires no Tailscale account or control server and is fully compatible with the stock Tailcat client.
Connections are established through a DERP relay and upgraded to a direct path when the network allows.

The networking stack runs entirely in userspace, with no TUN device, root privileges or routing changes required.
Incoming connections are exposed through `Server::accept_tcp` and `Server::accept_udp`.
The protocol core is `no_std` and requires only `alloc`, making it suitable for embedded and bare-metal targets, as described in [no_std](#no_std).

[Burrow](https://github.com/pixec/burrow), a microVM sandbox platform for running untrusted code on your own hardware, uses tailcat-rs to give Tailcat clients access to its sandboxes.

> [!WARNING]
> A server address contains its pre-shared key. Anyone holding the address can connect, so treat it as a secret.

> [!NOTE]
> tailcat-rs is not affiliated with or endorsed by Tailscale Inc.

## Usage

Run the example server:

```sh
cargo run --example serve -- 18080
```

It prints an address. Connect to it from another machine with the Go client:

```sh
tailcat <addr> 18080
```

## Services

tailcat-rs provides the Tailcat server's built-in services as handlers for connections accepted from `Server::accept_tcp` and `Server::accept_udp`:

- `SshHandler` serves SSH, conventionally on port 22. Clients authenticate with a key listed in `SshOptions::authorized_keys`, or through the tunnel alone. Sessions run a shell, a client command or a forced command, with optional PTY support.
- `FileService` configures the SFTP subsystem of `SshHandler`, rooted in a single directory and served read-only, read-write or write-only.
- `ExecHandler` runs a command for each connection, with the connection as its standard input and output.
- `PerfHandler` serves throughput and latency tests from `tailcat perf` on TCP and UDP port 5201.

These services are compatible with the Go client's `ssh`, `cp`, `ls` and `perf` commands.
Each is behind an opt-in cargo feature, `exec`, `ssh`, `sftp` or `perf`, none of which is enabled by default; `sftp` implies `ssh`.

## Relays

By default, tailcat-rs uses the same public relays as Tailcat.
As with Tailcat, a relay carries the connection until NAT traversal finds a direct path, and remains in use if none is found.

> [!IMPORTANT]
> The public relays are Tailscale's free, rate-limited servers.
> For anything beyond light use, [run your own `derper`](https://github.com/tailscale/tailscale/tree/main/cmd/derper#derp) and give the server a DERP map that lists it.

## no_std

The `std` feature, enabled by default, provides `Server` and everything it runs on: tokio, sockets, TLS, DERP map fetching and boringtun.
Without it, tailcat-rs is `no_std` and requires only `alloc`.

The core provides keys, addresses, DERP map types, the disco, meow and STUN messages, and sans-IO state machines for the DERP session, the transport and path selector, and the userspace TCP/UDP stack.
The caller supplies bytes, the current time and a cryptographic RNG, and sends whatever the state machines return.
WireGuard is supplied through the `tunnel::WireGuard` trait, since boringtun requires `std`.

The no_std build is checked against a bare-metal target:

```sh
rustup target add thumbv7em-none-eabihf
cargo build --no-default-features --target thumbv7em-none-eabihf
```

## Interop test

`tests/interop.rs` runs the Go client against tailcat-rs through a local relay.
It is ignored by default and needs two Go binaries:

```sh
git clone https://github.com/tailscale/tailcat.git && cd tailcat
go build -o tailcat-go ./cmd/tailcat
GOFLAGS=-mod=mod go build -o derper tailscale.com/cmd/derper
cd -
TAILCAT_GO=/path/to/tailcat-go DERPER=/path/to/derper cargo test --test interop -- --ignored --nocapture
```

`tests/interop_services.rs` runs the same client against the SSH, SFTP, exec and perf services:

```sh
TAILCAT_GO=/path/to/tailcat-go DERPER=/path/to/derper cargo test --all-features --test interop_services -- --ignored --nocapture
```

## License

tailcat-rs is licensed under the MIT License, in [LICENSE](LICENSE).
Portions are derived from Tailcat, licensed under the BSD 3-Clause License, in [NOTICE](NOTICE).
