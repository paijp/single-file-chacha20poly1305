# single-file-chacha20poly1305

- To encrypt on the embeded system and decrypt on the server, or vice versa, chacha20-poly1305 can be processed in a single file.
- It works if 32-bit integers are supported.

## USAGE

### C

```
#include "c20p1305.h"

{
	UB	key[32];
	UB	nonce[12];
	UB	work[****];
	UB	mac[16];
	UB	macnew[16];
	
/* send: work, mac <- work, key, nonce */
	
	c20p1305_xor(work, sizeof(work), key, nonce);
		/* work[] <- encrypt <- work[] */
	c20p1305_mac(mac, NULL, 0, work, sizeof(work), key, nonce);
		/* mac[] <- digest <- work[] */
	
/* receive: work <- mac, work, key, nonce */
	
	c20p1305_mac(newmac, NULL, 0, work, sizeof(work), key, nonce);
		/* newmac[] <- digest <- work[] */
	{
		UB	diff;
		W	i;
		
		diff = 0;
		for (i=0; i<sizeof(mac); i++)
			diff |= mac[i] ^ newmac[i];
		if ((diff))
			return -1;		/* digest not match */
	}
	c20p1305_xor(work, sizeof(work), key, nonce);
		/* work[] <- decrypt <- work[] */
}
```

### php

- The two `if (count(get_included_files()) <= 1) { ... }` blocks at the end of
  the source are self-tests that only run when the file is invoked directly
  (`php c20p1305.php`); when it is `require`d they are skipped automatically.

```
$plaintext = array();
$key = array();		# 32 elements
$nonce = array();		# 12 elements

# send: $ciphertext, $mac <- $plaintext, $key, $nonce
$chacha20 = new chacha20();
$ciphertext = $chacha20->crypt($plaintext, $key, $nonce);
$mac = c20p1305_mac(array(), $ciphertext, $key, $nonce);

# receive: $plaintext <- $mac, $ciphertext, $key, $nonce
$newmac = c20p1305_mac(array(), $ciphertext, $key, $nonce);
$diff = 0;
foreach ($newmac as $k => $v)
	$diff |= $v ^ $mac[$k];
if (($diff))
	dia("digest not match.\n");
$chacha20 = new chacha20();
$plaintext = $chacha20->crypt($ciphertext, $key, $nonce);


```


## SAMPLES

### `sample-host/` — receiver (PHP) with per-device pairing

A small PHP receiver that pairs with one device at a time via a generated
ChaCha20-Poly1305 key:

- `gen-key.sh` — generates a random 32-byte key, writes it to
  `keys/<random-id>`, and prints the matching `C20P:K:<hex>;U:<URL>;;`
  barcode both as text and as a UTF-8 QR rendering for terminal scanning.
- `index.php` — looks up the key by `?id=...`, verifies the Poly1305 MAC,
  and guards against replay using a single state file per id
  (`<last request hex>\\t<last response hex>`):
  - exact request match → return the cached response (idempotent retry)
  - nonce ≤ last → silent reject (replay, or nonce reuse with different
    body — a key-compromise signal)
  - otherwise → process and overwrite state atomically

See `sample-host/README.md` for setup, web-server config and security notes.

### `sample-32mx-wroom02/` — PIC32MX270 + ESP-WROOM-02 firmware

Companion firmware that pairs to the receiver above by reading two
independent barcodes (currently simulated by sending `X` or `Y` on
`/dev/ttyACM0`; the same hook can be driven by a real USB-HID scanner):

- `WIFI:T:WPA;S:<ssid>;P:<pass>;;` — Wi-Fi credentials.
- `C20P:K:<64 hex>;U:<full URL up to "key0c20=">;;` — ChaCha20 key + endpoint.

Both are persisted to internal flash. The boot path loads them, opens the
connection via the WROOM-02, and sends/receives nonce-prefixed,
Poly1305-authenticated bodies to the PHP receiver. The nonce counter itself
is also persisted across power loss in a separate redundant flash page pair.


## REFERENCE

- poly1305 from https://github.com/floodyberry/poly1305-donna
- test data from https://github.com/wg/c20p1305


## LICENSE

- MIT or PUBLIC DOMAIN.


## ATTRIBUTION

The `sample-host/` and `sample-32mx-wroom02/` directories — including the
pairing flow, the C20P barcode format, the flash-storage scheme, the
shell/PHP scaffolding and this README's SAMPLES section — were written by
Claude Opus 4.7 in a pair-programming session with the repository author
during 2026-06-27 / 2026-06-29.
