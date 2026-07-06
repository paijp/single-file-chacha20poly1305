#!/bin/sh
#
# Generate one fresh ChaCha20-Poly1305 key for the sample-host endpoint and
# print the matching C20P pairing barcode (text + UTF-8 QR) to stdout.
#
#   ./gen-key.sh [URL_BASE]
#
# URL_BASE  Full URL up to the receiver script's directory.
#           Default: http://localhost/wifi0/
#
# The generated barcode encodes the key + URL the device will hit:
#
#   C20P:K:<64 hex chars>;U:<URL_BASE>?id=<random>&key0c20=;;
#
# The random id is also the name of the file in $KEYS_DIR holding the key.
# Per-id state ("<last request hex>\t<last response hex>") is written by the
# receiver next to the key file, so $KEYS_DIR must be writable by the web
# server user. Restrict reads via nginx/apache (see README.md).
#
# Requires: openssl, qrencode.

set -eu

URL_BASE="${1:-http://localhost/wifi0/}"
KEYS_DIR="${KEYS_DIR:-$(dirname "$0")/keys}"

mkdir -p "$KEYS_DIR"

# 16 hex chars (64 bits) — opaque to the device. Used as both the key
# filename and the ?id= URL parameter.
id=$(openssl rand -hex 8)
hex=$(openssl rand -hex 32)

# Atomic write so a concurrent reader never sees a half-written key.
tmp="$KEYS_DIR/.$id.$$"
printf '%s' "$hex" > "$tmp"
chmod 640 "$tmp"
mv "$tmp" "$KEYS_DIR/$id"

# FIFO pair bridging the device to a local process:
#   to_<id>   — receiver writes each decrypted device payload here
#   from_<id> — bytes queued here (max 200/request) ride back in the reply
# Both are used non-blocking, best-effort; see index.php.
mkfifo -m 660 "$KEYS_DIR/to_$id" "$KEYS_DIR/from_$id"

barcode="C20P:K:${hex};U:${URL_BASE}?id=${id}&key0c20=;;"
printf '%s\n\n' "$barcode"
printf '%s' "$barcode" | qrencode -t UTF8 -m 2
