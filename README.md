# bwrap-winer

`bwrap-winer` is a lightweight, zero-flag Unix-style sandbox proxy designed to run Windows applications via Wine inside highly isolated **Bubblewrap (`bwrap`)** containers.

We adhere strictly to the UNIX philosophy: *"Do one thing and do it well."*

---

## Key Features

- **Zero-Flags Architecture**: No complex CLI flags. All command-line arguments passed to `bwrap-winer` after the executable are forwarded directly to the sandboxed Wine application.
- **Dynamic Configuration Pyramid**: Resolves configurations hierarchically:
  `Environment Variables -> Local Sandbox Meta (TOML) -> User Config (TOML) -> Global Config (TOML) -> Defaults`.
- **Custom Engine Auto-Mounting**: Specify a custom Wine binary via `WINER_WINE_PATH`. The tool automatically identifies its root (supporting standard Wine & Proton layouts), binds it read-only, and injects correct library paths dynamically.
- **Shared Path Exclusion**: Prevents auto-mounting broad shared directories (e.g., `/usr`, `/opt`, `/mnt`, `$HOME`) to maintain strict security boundaries.
- **Process Lifecycle Binding**: Forces `--die-with-parent` in Bubblewrap. If the sandbox or parent process dies, all background `wineserver` and subprocesses are terminated immediately by the kernel.
- **Security-First**: Blocks execution of native Linux ELF binaries inside the sandbox, ensuring it functions strictly as a Wine proxy.

---

## Directory Structure Specification (XDG Compliant)

```text
~/.config/bwrap-winer/
├── config.toml              # General configuration
└── IDs
    └── [WINER_ID].toml      # User configuration

~/.local/share/bwrap-winer/sandboxes/[WINER_ID]/
├── winer_meta.toml          # Local configuration overrides for this sandbox
└── sandbox_home/            # Isolated virtual HOME directory
    └── .wine/               # Sandboxed Wine Prefix
```

---

## Configuration Variables & Environment Keys

All keys can be declared either as host environment variables or as key-value pairs inside standard configuration TOML files.

| Variable Name | Default | Description |
|---|---|---|
| `WINER_EXE_PATH` | Empty | Target executable file path (can substitute CLI argument). |
| `WINER_EXE_ARGS` | Empty | Arguments to pass to the target executable. |
| `WINER_EXE_PRE` | Empty | Custom launcher prefix command chain (e.g., `~/patch/patcher.exe`). |
| `WINER_WINE_PATH` | `wine` | Custom Wine binary path to use instead of system 'wine'. |
| `WINER_ID` | Auto-Hash | Explicit override for the unique sandbox identifier. |
| `WINER_DATA_ROOT` | XDG default | Alternative root directory path for sandboxes storage. |
| `WINER_NET` | `1` | Network access control: '1' (shared, default) or '0' (disconnected). |
| `WINER_SHARE_PID` | `1` | PID namespace sharing: '1' (shared, default) or '0' (strict process isolation). |
| `WINER_IPC` | `1` | IPC namespace sharing: '1' (shared, default) or '0' (isolated with performance warning). |
| `WINER_DEV` | `1` | Input hardware pass-through: '1' (full /dev bind, default) or '0' (DRI & NVIDIA only). |
| `WINER_DESKTOP` | Empty | Virtual desktop resolution wrapper (e.g., '1920x1080', '1280x720', default: disabled). |
| `WINER_PENETRATE` | `1` | File mounting penetration depth: '0' (file-only), '1' (parent, default), or 'n' (n-th parent). |
| `WINER_GAMEMODE` | `0` | GameMode high-performance wrapping: '1' (enable gamemoderun) or '0' (disabled, default). |
| `WINER_BIND` | Empty | Comma-separated read-write paths to mount (e.g., `/host_dir:/sandbox_dir`). |
| `WINER_RO_BIND` | Empty | Comma-separated read-only paths to mount (e.g., `/host_dir:/sandbox_dir`). |
| `WINEPREFIX` | Empty | Specific Host Wine prefix to automatically pass-through and heal. |

---

## Quick Start

### 1. Basic Usage
Run an installer or application transparently:
```bash
bwrap-winer WeChatSetup.exe
```

### 2. Run with Custom Engine (Proton/Lutris)
`bwrap-winer` will dynamically discover the root structure of the runner and mount it safely:
```bash
bwrap-winer /home/user/runners/wine-version/bin/wine WeChatSetup.exe
```

### 3. Or you can run like this:
`bwrap-winer` will not alter the original behavior of `wine`
```bash
WINER_ID=test \
      WINER_WINE_PATH="/home/user/runners/wine-version/bin/wine" \
      WINER_BIND="/home/user/Games" \
      WINER_RO_BIND="/home/user/Downloads" \
      WINER_EXE_PATH="" \
      WINER_EXE_ARGS="" \
      WINEPREFIX="/home/user/prefixes/test_prefix" \
      bwrap-winer cmd
```

### 4. List active sandboxes
```bash
bwrap-winer --list
```

---

## 🛠️ Build Guide

This project can be built either for local development/testing or cross-compiled into multi-architecture, statically-linked binaries with zero external runtime dependencies.

### Prerequisites
* **Rust Toolchain**: Install via `rustup` (standard stable channel is recommended).
* **Bubblewrap**: Ensure `bwrap` is installed on your host system (e.g., `sudo pacman -S bubblewrap` on Arch Linux or `sudo apt install bubblewrap` on Debian/Ubuntu).

---

### Makefile Reference

A GNU `Makefile` is provided to automate compilation, environment setup, and cross-compilation targets.

| Command | Description |
| :--- | :--- |
| `make setup` | Checks and automatically installs the target toolchains (`x86_64` and `aarch64` musl) via rustup. |
| `make build` | Compiles the native release binary and places it under `./bin/bwrap-winer`. |
| `make run` | Compiles and immediately executes the local binary with the `--help` flag. |
| `make release` | Cross-compiles statically-linked musl binaries for both AMD64 and ARM64 into `./builds/`. |
| `make clean` | Cleans up cargo caches, `./bin/`, and `./builds/` build directories. |
| `make help` | Displays the help menu with all available targets. |

---

### Step-by-Step Compilation

#### 1. Local Development & Native Build
To build the native binary for your current CPU architecture and test it locally:
```bash
# Build the binary
make build

# Run the proxy help menu
./bin/bwrap-winer --help
```

#### 2. Multi-Architecture Static Distribution
To prepare release-ready, static binaries for distribution:
```bash
make release
```
This will compile and generate two statically linked, stripped binaries inside the `./builds/` directory:
* `builds/bwrap-winer_linux_amd64` (AMD64 Static)
* `builds/bwrap-winer_linux_arm64` (ARM64 Static)

#### 🔍 Behind the Magic (Self-Contained Linker)
The `make release` command leverages Rust's built-in LLD linker (`rust-lld`) combined with the compiler flag `-C link-self-contained=yes`. 

This enables **seamless cross-compilation** without requiring you to install multi-arch dynamic headers, libraries, or external GNU compilers (like `aarch64-linux-gnu-gcc`) on your host machine.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
