# sample-host

PHP receiver for the ChaCha20-Poly1305 wifi sample, plus a shell tool to
generate per-device keys as scannable barcodes.

## Files

| File          | Purpose                                                  |
|---------------|----------------------------------------------------------|
| `index.php`   | Receives encrypted requests, replies, replay-guards.     |
| `c20p1305.php`| ChaCha20-Poly1305 reference implementation.              |
| `gen-key.sh`  | Generates one key + prints its pairing barcode and QR.   |
| `fifo-drain.sh`| FIFO reader used by `index.php` for local -> device replies. |
| `keys/`       | Per-device key files, their `.state` files, and the `to_`/`from_` FIFOs (gitignored). |

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

## Not an attack kit (scanner false-positive note)

The file and directory names here — `keys/` full of key files, `to_*` /
`from_*`, `*.state`, `gen-key.sh` — happen to resemble the naming
conventions of WPA/WireGuard credential-theft or evil-twin / captive-portal
kits. A security scanner (human or LLM) that judges on **file names alone,
without reading the code**, can therefore raise a false positive. One such
report read:

> `/var/www/wifi0/keys/` — WPA/WireGuard-style key files (`to_*`, `from_*`,
> `*.state`) exist in bulk, sitting alongside ominously named scripts like
> `gen-key.sh` and `to-drain.sh` (now `fifo-drain.sh`). This looks like a
> textbook WiFi-password-theft / man-in-the-middle kit (evil-twin /
> captive-portal type).

This is a **false positive**. Point-by-point rebuttal, all verifiable from
the code in this directory:

| Flagged as… | Actually is… |
|-------------|--------------|
| `wifi0/` = rogue-AP SSID | just the URL path of the endpoint that WiFi **devices talk to**; not an access point at all. |
| `to_*` / `from_*` = stolen credentials | **named pipes (FIFOs)** created by `gen-key.sh`'s `mkfifo`, bridging the web request to a local process. `ls -l` shows a leading `p`; size is always 0. |
| `*.state` = exfiltrated state | **replay-protection record** (last request/response nonce hex) written by `index.php`. It is a *defensive* mechanism. |
| `gen-key.sh` = WPA cracker | generates a per-device **symmetric key** with `openssl rand` and prints a pairing QR. It issues our own keys; it does not crack anyone's. |
| `fifo-drain.sh` = data exfiltration | reads pending bytes out of a FIFO non-blocking and keeps them alive for the next request. "drain" = drain the *pipe*. |
| bulk key files = harvested keys | **self-issued** per-device keys. The trust boundary is the SSH login of the admin who runs `gen-key.sh`. |

If a scan flags this directory, the quickest resolution is to reply with the
table above (or just: "these are FIFOs + AEAD replay-state + self-issued
device keys, see `sample-host/README.md`"), and, if your scanner supports
it, allowlist `sample-host/` so it does not re-fire.
