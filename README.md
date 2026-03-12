# SmartBlock

An eBPF-based IP blocking tool with **Proxy Protocol v1/v2** support, designed for high-performance security in modern Linux environments.

---

## 🚀 Features

- **High Performance**: Leverages eBPF/XDP for packet filtering at the lowest level of the network stack.
- **Proxy Aware**: Supports Proxy Protocol v1 and v2 to identify real client IPs behind load balancers.
- **Flexible Management**:
  - **Global**: Block IPs across the entire interface.
  - **Group-based**: Target specific server-client pairs using logical groups.
- **Rule Persistence**: Optional `--keep` flag to maintain blocking rules even after the main process exits.
- **Stats Tracking**: Real-time packet and byte count for blocked traffic.

---

## 🛠 Prerequisites

### System Requirements

- **OS**: Linux (tested on Ubuntu 18.04/20.04)
- **Kernel**: >= 5.4 recommended (requires XDP support)
- **Dependencies**:
  ```bash
  sudo apt install -y build-essential pkg-config libssl-dev libgit2-dev
  ```

### Rust Toolchain

```bash
# Install Stable & Nightly (Nightly required for eBPF source)
rustup toolchain install stable
rustup toolchain install nightly --component rust-src

# Install BPF Linker
cargo install bpf-linker
```

---

## 🏗 Build & Run

### 1. Build

```bash
# Standard Build
cargo build

# Release Build (Static linking for distribution)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

### 2. Run

```bash
# Basic run (Interface ens160)
sudo ./target/debug/smart-block --iface ens160

# Run with persistence & debug logs
sudo ./target/debug/smart-block --iface ens160 --keep --debug
```

### 💡 Options Reference

| Flag      | Description                                            | Default  |
| :-------- | :----------------------------------------------------- | :------- |
| `--iface` | Network interface to attach the XDP program.           | `ens160` |
| `--debug` | Enable eBPF kernel debug logs (`trace_pipe`).          | `false`  |
| `--keep`  | Persist BPF maps (rules) at `/sys/fs/bpf/` after exit. | `false`  |

---

## 📖 Usage Guide

### Global IP Management

Manage the main blacklist applicable to the entire interface.

```bash
# Add an IP to blacklist
sudo ./smart-block add [IP_ADDRESS]

# Remove an IP
sudo ./smart-block remove [IP_ADDRESS]

# List all blocked IPs and stats
sudo ./smart-block list
```

### Group-based Management

Manage blocking for specific virtual groups (useful for multi-tenant setups).

```bash
# Add client to a group for a specific server IP
sudo ./smart-block group add [GROUP_NAME] [SERVER_IP] [CLIENT_IP]

# Remove from group
sudo ./smart-block group remove [GROUP_NAME] [SERVER_IP] [CLIENT_IP]

# List all group configurations
sudo ./smart-block group list
```

---

## 🐧 Supported Systems

- **Ubuntu 18.04/20.04**: Kernel `5.4.0-58-generic` (Tested)
- **Generic Linux**: Any distribution with XDP support (Kernel >= 5.4)

---

## 🍎 Cross-compilation (macOS)

Develop on macOS and compile for Linux using `musl`.

```bash
# Tools
brew install llvm filosottile/musl-cross/musl-cross

# Build
CC=${ARCH}-linux-musl-gcc cargo build --package smart-block --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

> _Note: Replace `${ARCH}` with `x86_64` or `aarch64`._

---

## 📜 License

- **General**: Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
- **eBPF Code**: Dual-licensed under [GPL-2.0](LICENSE-GPL2) or [MIT](LICENSE-MIT).
