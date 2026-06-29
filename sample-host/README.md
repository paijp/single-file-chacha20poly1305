# sample-host

PHP receiver for the ChaCha20-Poly1305 wifi sample, plus a shell tool to
generate per-device keys as scannable barcodes.

## Files

| File          | Purpose                                                  |
|---------------|----------------------------------------------------------|
| `index.php`   | Receives encrypted requests, replies, replay-guards.     |
| `c20p1305.php`| ChaCha20-Poly1305 reference implementation.              |
| `gen-key.sh`  | Generates one key + prints its pairing barcode and QR.   |
| `keys/`       | Per-device key files and their `.state` files (gitignored). |

## Pairing flow

1. Admin SSHes into the host and runs
   `./gen-key.sh https://example.com/wifi0/`
   which prints a `C20P:K:...;U:...;;` string and renders a QR code in the
   terminal.
2. The device's barcode reader scans the QR. The firmware parses it, stores
   the key+URL in flash, and starts sending encrypted requests.
3. Each request comes back through `index.php`, which looks up the key by
   id, verifies the MAC, checks for nonce monotonicity, and replies.

A successful scan = pairing complete. There is no admin web UI: the SSH login
is the trust boundary, the per-device key is the credential.

## Setup

```sh
# Install qrencode if needed.
sudo apt-get install qrencode    # or: dnf install qrencode

# Make sure keys/ is writable by the web server (it stores per-id .state
# files alongside the key files).
chown www-data:www-data keys/    # adapt user to your web server
chmod 770 keys/
```

Deny direct web access to `keys/`. Example for nginx:

```nginx
location ^~ /wifi0/keys/ { deny all; }
```

(Or place `keys/` outside the web root and set `$keys_dir` in `index.php`
accordingly.)

## Security notes

- **Each id is single-use per pairing.** If the same `gen-key.sh` output is
  scanned by two devices they will fight over the same `.state` file; the
  receiver has no enforcement here, that's an operational rule.
- **`nonce <= last` rejection covers two cases**: a classic replay (older
  nonce) and "same nonce, different body" — the latter shouldn't happen with
  a well-behaved firmware and would be a key-compromise signal. Both are
  silently dropped. Add `error_log()` at that branch if you want alerts.
- **Rate-limit the receiver** at the proxy if it's exposed to the open
  internet:
  ```nginx
  limit_req_zone $binary_remote_addr zone=wifi0:1m rate=10r/s;
  location /wifi0/ { limit_req zone=wifi0 burst=20 nodelay; ... }
  ```
- **Key rotation** = run `gen-key.sh` again and re-pair the device. Old key
  files can be deleted; the matching `.state` file is harmless if left
  behind.
- **HTTPS** is recommended even though every request body is authenticated
  end-to-end: it hides the id and prevents man-in-the-middle from learning
  pairing URLs.
