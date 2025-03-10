# single-file-chacha20poly1305

- To encrypt on the embeded system and decrypt on the server, or vice versa, chacha20-poly1305 can be processed in a single file.

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

- The if ((1)) in the source code is test code. Disable it when used.

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


## REFERENCE

- poly1305 from https://github.com/floodyberry/poly1305-donna
- test data from https://github.com/wg/c20p1305


## LICENSE

- MIT or PUBLIC DOMAIN.
