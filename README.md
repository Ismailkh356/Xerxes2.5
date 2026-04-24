# Tsunami

**Tsunami** is a command-line HTTP/2 stress-testing tool intended for **authorized security testing** and lab environments.

> This repository is maintained by **Ismailkh356**.

## Legal disclaimer

This project is for **AUTHORIZED SECURITY TESTING ONLY**. You must have explicit written permission from the system owner before using this tool. Unauthorized use may be illegal and unethical.

## Features

- HTTP/2 support (multiplexing)
- TLS/SSL (ALPN negotiation)
- High concurrency
- Custom headers / payloads
- Basic live statistics (depending on build/options)

> Note: Feature availability depends on the current implementation in this repository.

---

## Installation

### 1) Install build dependencies

#### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y git build-essential libnghttp2-dev libssl-dev
```

#### Fedora/RHEL

```bash
sudo dnf install -y git gcc gcc-c++ make libnghttp2-devel openssl-devel
```

#### Arch

```bash
sudo pacman -S --needed git base-devel nghttp2 openssl
```

### 2) Clone the repository

```bash
git clone https://github.com/Ismailkh356/Tsunami.git
cd Tsunami
```

### 3) Build

If the repo includes a Makefile:

```bash
make
```

If the repo ships a single C/C++ file (example build command):

```bash
# Example only — adjust filename/output to match this repo
gcc -O2 -o tsunami *.c -lnghttp2 -lssl -lcrypto -lpthread
```

### 4) (Optional) Install system-wide

```bash
sudo install -m 0755 tsunami /usr/local/bin/tsunami
```

---

## Usage

Run the tool with `--help` (or `-h`) to see all options supported by your current build:

```bash
./tsunami --help
# or, if installed system-wide
tsunami --help
```

### Example commands (authorized testing only)

> Replace `https://example.com/` with a target you own or have written permission to test.

**Basic test (HTTPS / HTTP/2):**

```bash
./tsunami https://example.com/
```

**Run for a fixed duration (example: 30 seconds):**

```bash
./tsunami https://example.com/ --duration 30
```

**Increase concurrency (example: 200 connections):**

```bash
./tsunami https://example.com/ --connections 200
```

**Set a request rate limit (example: 500 req/s):**

```bash
./tsunami https://example.com/ --rate 500
```

**Add a custom header:**

```bash
./tsunami https://example.com/ --header "User-Agent: TsunamiLab" --header "X-Test: 1"
```

---

## Troubleshooting

### "command not found"

- If you built locally, run it with `./tsunami` from the repo directory.
- If you installed it, make sure `/usr/local/bin` is on your `PATH`.

### Build errors about nghttp2 / OpenSSL

- Ensure you installed the dev packages:
  - `libnghttp2-dev` (Debian/Kali) or `libnghttp2-devel` (Fedora)
  - `libssl-dev` / `openssl-devel`

### Still stuck?

Open an issue and include:
- Your OS
- The exact command you ran
- The full error output

---

## License

Add a license file to this repository (for example, MIT) and keep it consistent with any third-party code included.
