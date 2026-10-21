#!/usr/bin/env bash
set -euo pipefail

version="2.42.1"
sha256="6ff270c9bf07d2bec5c98aa324eb7c4daf6a1a4d815c05ff1708049616047855"
asset="mold-${version}-x86_64-linux.tar.gz"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

curl --fail --location --silent --show-error \
  --connect-timeout 15 --max-time 120 --retry 3 --retry-all-errors \
  --proto '=https' --tlsv1.2 \
  "https://github.com/rui314/mold/releases/download/v${version}/${asset}" \
  -o "${tmp_dir}/${asset}"

echo "${sha256}  ${tmp_dir}/${asset}" | sha256sum --check --status

sudo tar -xzf "${tmp_dir}/${asset}" -C /usr/local --strip-components=1
mold --version
ld.mold --version
