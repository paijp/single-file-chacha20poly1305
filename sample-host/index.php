<?php

/*
	Single file chacha20poly1305 https://github.com/paijp/single-file-chacha20poly1305

	License: MIT or PUBLIC DOMAIN.

	Receiver for the C20P-barcode pairing flow (see gen-key.sh).

	URL:  ?id=<random>&key0c20=<request hex>

	The id is the opaque filename of the per-device key under ./keys/. The
	matching .state file (single line "<last request hex>\t<last response
	hex>") gives replay/retry handling without a database.

	No HTTP-level auth: the key acts as the credential, and the MAC + nonce
	monotonicity verify both authenticity and freshness.
*/

require("c20p1305.php");

$keys_dir = __DIR__ . "/keys";

/* id: alnum, 4..32 chars. Pattern is tight enough that "..", "/", etc. can't
   slip in, so the concatenation below is safe. */
$id = $_GET["id"] ?? "";
if (!preg_match('/^[0-9A-Za-z]{4,32}$/', $id))
	die();

$key_file = "$keys_dir/$id";
if (!is_file($key_file))
	die();
$keyhex = trim((string)@file_get_contents($key_file));
if (!preg_match('/^[0-9a-fA-F]{64}$/', $keyhex))
	die();
$key = array();
$bin = hex2bin($keyhex);
for ($i=0; $i<32; $i++)
	$key[] = ord(substr($bin, $i, 1));

$req_hex = strtolower((string)($_GET["key0c20"] ?? ""));
if (!preg_match('/^[0-9a-f]+$/', $req_hex) || strlen($req_hex) < 56)
	die();

$bin = hex2bin($req_hex);
$a = array();
for ($i=0; $i<strlen($bin); $i++)
	$a[] = ord(substr($bin, $i, 1));

$nonce = array_slice($a, 0, 12);
$body  = array_slice($a, 12, count($a) - 28);
$tag   = array_slice($a, count($a) - 16);

/* Authenticate. cmp_array dies on mismatch. */
cmp_array($tag, c20p1305_mac(array(), $body, $key, $nonce));

/* Replay / retry guard.

   State file holds "<last request hex>\t<last response hex>" (one line). The
   first 24 hex chars are the nonce — comparing them lexicographically is the
   same as the byte-wise numeric compare the firmware does.

     req == last         → idempotent retry, return cached response
     nonce(req) <= last  → replay (older) or nonce reuse with different body
                           (key compromise / firmware bug) → silent reject
     otherwise           → fresh, process and overwrite state
*/
$state_file = "$keys_dir/$id.state";
$last = @file_get_contents($state_file);
if ($last !== false) {
	$parts = explode("\t", trim($last), 2);
	$lreq  = $parts[0] ?? "";
	$lresp = $parts[1] ?? "";
	if ($req_hex === $lreq) {
		print "key0c20=$lresp\n\n";
		exit;
	}
	if (substr($req_hex, 0, 24) <= substr($lreq, 0, 24))
		die();
}

/* Decrypt incoming body. */
$c = new chacha20();
$out = $c->crypt($body, $key, $nonce);

/* Only the even-nonce[11] direction expects a reply (existing convention). */
if (($nonce[11] & 1))
	die();
$nonce[11] |= 1;

/*
	Bridge to local processes (both created by gen-key.sh):

	from_<id> — FIFO, device -> local, log-style. Each decrypted device
	payload is written non-blocking; a local `cat <>keys/from_<id>` tails
	it. If nobody holds the FIFO open the bytes are dropped (best effort).

	to_<id> — regular append-spool file + to_<id>.pos offset, local ->
	device. Writers just `printf '...' >> keys/to_<id>`; O_APPEND makes
	concurrent appends atomic and closing loses nothing. Up to 200 bytes
	per request are read from the stored offset (the firmware's recvbuf is
	256: 12 nonce + 200 body + 16 tag). Once fully drained past 64 KiB the
	spool is truncated under flock; wrap appends in flock(1) too if the
	instant of that truncation matters.

	Without these files (old ids), fall back to echoing the payload + 0x72.
*/
$from_fifo = "$keys_dir/from_$id";
$to_spool  = "$keys_dir/to_$id";
$to_pos    = "$keys_dir/to_$id.pos";
if (file_exists($from_fifo) && file_exists($to_spool)) {
	$fh = @fopen($from_fifo, "r+");	/* r+ never blocks on a FIFO */
	if ($fh) {
		stream_set_blocking($fh, false);
		$s = "";
		foreach ($out as $c)
			$s .= chr($c);
		@fwrite($fh, $s);
		fclose($fh);
	}
	$reply_src = array();
	$fh = @fopen($to_spool, "r");
	if ($fh) {
		flock($fh, LOCK_EX);
		$pos = (int)@file_get_contents($to_pos);
		fseek($fh, $pos);
		$s = (string)@fread($fh, 200);
		$pos += strlen($s);
		$size = fstat($fh)['size'];
		if ($pos >= $size && $size > 65536) {
			/* fully drained and grown large: reset the spool */
			$wh = fopen($to_spool, "r+");
			ftruncate($wh, 0);
			fclose($wh);
			$pos = 0;
		}
		file_put_contents($to_pos, (string)$pos);
		flock($fh, LOCK_UN);
		fclose($fh);
		for ($i=0; $i<strlen($s); $i++)
			$reply_src[] = ord(substr($s, $i, 1));
	}
	$out = $reply_src;
} else {
	$out[] = 0x72;	/* response marker (echo mode) */
}

$c = new chacha20();
$reply    = $c->crypt($out, $key, $nonce);
$replytag = c20p1305_mac(array(), $reply, $key, $nonce);

$resp_hex = "";
foreach ($nonce as $c)    $resp_hex .= sprintf("%02x", $c);
foreach ($reply as $c)    $resp_hex .= sprintf("%02x", $c);
foreach ($replytag as $c) $resp_hex .= sprintf("%02x", $c);

/* Persist <request, response> atomically (tmp + rename). Same-id concurrency
   is assumed not to happen — a device only retries serially. */
$tmp = "$state_file." . getmypid();
file_put_contents($tmp, "$req_hex\t$resp_hex");
rename($tmp, $state_file);

print "key0c20=$resp_hex\n\n";
