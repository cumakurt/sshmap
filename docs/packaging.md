# Packaging and Distribution

SSHMap ships as a single static binary with optional Linux packages and a container image.

## Release Binary

Build locally:

```bash
cargo build --release
./target/release/sshmap --version
```

Or use the helper script:

```bash
./packaging/build-packages.sh
```

Artifacts are written to `dist/`:

- `sshmap` binary
- `SHA256SUMS`
- `.deb` and `.rpm` packages when `nfpm` is installed

## Linux Packages

Install [nfpm](https://nfpm.goreleaser.com/) and run:

```bash
SSHMAP_VERSION=1.0.0 ./packaging/build-packages.sh
```

Package metadata is defined in `packaging/nfpm.yaml`.

## Container Image

Build from the repository root after producing `dist/sshmap`:

```bash
./packaging/build-packages.sh
docker build -f packaging/Dockerfile -t sshmap:local .
```

Example usage:

```bash
docker run --rm -v "$PWD:/data" sshmap:local doctor
docker run --rm -v "$PWD:/data" sshmap:local db stats --db /data/sshmap.db
```

## GitHub Releases

Tagged releases (`v*`) build Linux x86_64, Linux aarch64, macOS aarch64, and macOS x86_64 binaries, a prebuilt React dashboard tarball (`sshmap-dashboard.tar.gz`), SHA256 checksums, and a CycloneDX SBOM through `.github/workflows/release.yml`.

Optional GPG signatures:

1. Add repository secrets `GPG_PRIVATE_KEY` and optionally `GPG_PASSPHRASE`
2. Release workflow signs `dist/SHA256SUMS` automatically when the key is configured

Sign checksums locally:

```bash
./packaging/sign-checksums.sh dist/SHA256SUMS
```

## Install Script

For development workstations, use `./install.sh` to detect the OS, verify dependencies, install only missing packages, build from source, copy the binary to `~/.local/bin`, and configure your shell `PATH`. Run `./install.sh --dry-run` to preview actions without making changes.
