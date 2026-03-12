# smart-block

An eBPF-based IP blocking tool with Proxy Protocol v1 v2 support.

## Prerequisites

To build and run `smart-block`, you need the following dependencies:

### Linux

```bash
sudo apt install -y build-essential pkg-config libssl-dev libgit2-dev
```

### Rust Toolchain

- **Stable & Nightly**:
  ```bash
  rustup toolchain install stable
  rustup toolchain install nightly --component rust-src
  ```
- **BPF Linker**:
  ```bash
  cargo install bpf-linker
  ```

## Build & Run

### Debug Build

```bash
# The build script automatically handles eBPF compilation
cargo build

# Run with debug logging
sudo ./target/debug/smart-block --iface [INTERFACE] --debug
```

### Release Build (Static Linking)

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Resulting binary:
# target/x86_64-unknown-linux-musl/release/smart-block
```

## Usage

### Options

| Flag      | Description                                                                                         |
| --------- | --------------------------------------------------------------------------------------------------- |
| `--iface` | Network interface to attach the XDP program (default: `ens160`).                                    |
| `--debug` | Enable debug logging in the eBPF program.                                                           |
| `--keep`  | Do not remove pinned BPF maps from `/sys/fs/bpf/` upon exit. This allows blocking rules to persist. |

### Global IP Management

Manage global blacklisted IPs.

```bash
sudo ./smart-block --iface ens192

sudo ./smart-block add [IP_ADDRESS]
sudo ./smart-block remove [IP_ADDRESS]
sudo ./smart-block list
```

### Group-based IP Management

Manage IP blocking based on specific server addresses and group names (useful for multi-tenant environments).

```bash
# Add a client IP to a specific group associated with a server
sudo ./smart-block group add [GROUP_NAME] [SERVER_IP] [CLIENT_IP]

# Remove from group
sudo ./smart-block group remove [GROUP_NAME] [SERVER_IP] [CLIENT_IP]

# List all group configurations
sudo ./smart-block group list
```

## Supported Systems

The following kernel versions have been tested and are confirmed to be compatible:

- Ubuntu 18.04/20.04 (Kernel **5.4.0-58-generic**)
- Any Linux distribution with XDP support (Kernel >= 5.4 recommended)

## Cross-compilation (macOS)

If you are developing on macOS, you can cross-compile to Linux using `musl`.

```bash
# Prerequisites for macOS
brew install llvm
brew install filosottile/musl-cross/musl-cross

# Build command
CC=${ARCH}-linux-musl-gcc cargo build --package smart-block --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

_Note: Replace `${ARCH}` with `x86_64` or `aarch64` depending on your target._

## License

With the exception of eBPF code, `smart-block` is distributed under the terms of either the [MIT license] or the [Apache License] (version 2.0).

All eBPF code is distributed under either the terms of the [GNU General Public License, Version 2] or the [MIT license].

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
