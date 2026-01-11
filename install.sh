#!/usr/bin/env bash
set -euo pipefail

REPO="jimmyzhou521-stack/TitanDNS"
VERSION="${1:-latest}"
OS="Linux"
ARCH_RAW=$(uname -m)
ARCH=""
cpu_supports_v3() {
  if [[ -r /proc/cpuinfo ]]; then
    local flags
    flags=$(grep -m1 -o 'flags.*' /proc/cpuinfo || true)
    for f in avx2 fma bmi1 bmi2 sse4_2; do
      echo "$flags" | grep -qw "$f" || return 1
    done
    return 0
  fi
  return 1
}
case "$ARCH_RAW" in
  x86_64|amd64)
    if cpu_supports_v3; then
      ARCH="x86_64-v3"
    else
      ARCH="x86_64"
    fi
    ;;
  aarch64|arm64) ARCH="arm64" ;;
esac

if [[ "$OS" != "Linux" ]]; then
  echo "Only Linux is supported by this installer." >&2
  exit 1
fi

if [[ -z "$ARCH" ]]; then
  echo "Unsupported architecture: $ARCH_RAW" >&2
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found. Please install curl first." >&2
  exit 1
fi

api_url="https://api.github.com/repos/${REPO}/releases/latest"
if [[ "$VERSION" != "latest" ]]; then
  api_url="https://api.github.com/repos/${REPO}/releases/tags/${VERSION}"
fi

asset_url=$(curl -fsSL "$api_url" | grep -Eo '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' | cut -d '"' -f4 | grep -- "-${OS}-${ARCH}\.tar\.gz" | head -n1 || true)
if [[ -z "$asset_url" && "$ARCH" == "x86_64-v3" ]]; then
  ARCH="x86_64"
  asset_url=$(curl -fsSL "$api_url" | grep -Eo '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' | cut -d '"' -f4 | grep -- "-${OS}-${ARCH}\.tar\.gz" | head -n1 || true)
fi
checksum_url=$(curl -fsSL "$api_url" | grep -Eo '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]+"' | cut -d '"' -f4 | grep -- "SHA256SUMS\.txt" | head -n1 || true)

if [[ -z "$asset_url" ]]; then
  echo "Failed to find release asset for ${OS}." >&2
  exit 1
fi

tmp_dir=$(mktemp -d)
archive="$tmp_dir/titandns.tar.gz"
archive_name=$(basename "$asset_url")

curl -fsSL -o "$archive" "$asset_url"

# Verify checksum if available
if command -v sha256sum >/dev/null 2>&1; then
  if [[ -n "$checksum_url" ]]; then
    curl -fsSL -o "$tmp_dir/SHA256SUMS.txt" "$checksum_url"
    expected=$(grep " $archive_name$" "$tmp_dir/SHA256SUMS.txt" | awk '{print $1}' || true)
    if [[ -n "$expected" ]]; then
      actual=$(sha256sum "$archive" | awk '{print $1}')
      if [[ "$actual" != "$expected" ]]; then
        echo "Checksum mismatch for $archive_name" >&2
        exit 1
      fi
    else
      echo "Warning: checksum not found for $archive_name, skipped verify." >&2
    fi
  else
    echo "Warning: SHA256SUMS.txt not found in release assets, skipped verify." >&2
  fi
else
  echo "Warning: sha256sum not found, skipped verify." >&2
fi

mkdir -p "$tmp_dir/pkg"
tar -xzf "$archive" -C "$tmp_dir/pkg"

if [[ ! -f "$tmp_dir/pkg/install.sh" ]]; then
  echo "install.sh not found in package." >&2
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  sudo bash "$tmp_dir/pkg/install.sh"
else
  bash "$tmp_dir/pkg/install.sh"
fi
