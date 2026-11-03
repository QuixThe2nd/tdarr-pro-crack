#!/bin/sh
set -eu

python3 -B -I /opt/tdarr-addon/native_verifier.py patch-in-place \
  --path /app/Tdarr_Server/rust/Tdarr_Server_Rust
exec /init "$@"
