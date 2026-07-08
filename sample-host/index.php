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
   first 24 hex chars are the nonce; its lowest bit is a flag, not part of
   the counter — the device sets it when it does NOT want a response.
   Comparing the flag-masked nonces lexicographically equals the byte-wise
   numeric compare the firmware does.

     nonce == last nonce (incl. flag) → idempotent retry, return cached
     masked nonce > masked last      → fresh, process and overwrite state
     otherwise                        → silent reject (replay / reuse)
*/
function nonce_masked($n)
{
	return substr($n, 0, 23) . dechex(hexdec(substr($n, 23, 1)) & 0xe);
}

$state_file = "$keys_dir/$id.state";
$cur_nonce = substr($req_hex, 0, 24);
$last = @file_get_contents($state_file);
if ($last !== false) {
	$parts = explode("\t", trim($last), 2);
	$lreq  = $parts[0] ?? "";
	$lresp = $parts[1] ?? "";
	$lnonce = substr($lreq, 0, 24);
	if ($cur_nonce === $lnonce) {
		if ($lresp !== "")
			print "key0c20=$lresp\n\n";
		exit;
	}
	if (nonce_masked($cur_nonce) <= nonce_masked($lnonce))
		die();
}

/* Decrypt incoming body. */
$c = new chacha20();
$out = $c->crypt($body, $key, $nonce);

/* nonce[11] LSB set = the device does not want a response. The payload is
   still delivered to from_<id> and the state still advances; only the
   to_<id> drain and the encrypted reply are skipped. */
$wantreply = !($nonce[11] & 1);
$nonce[11] |= 1;

/*
	Bridge to local processes (both FIFOs, created by gen-key.sh):

	from_<id> — device -> local, log-style. Each decrypted device payload
	is written non-blocking; a local `cat <>keys/from_<id>` tails it. If
	nobody holds the FIFO open the bytes are dropped (best effort).

	to_<id> — local -> device. Writers just `printf '...' > keys/to_<id>`.
	to-drain.sh reads up to 200 bytes per request (the firmware's recvbuf
	is 256: 12 nonce + 200 body + 16 tag) and parks a detached 10 s holder
	on the pipe, so unread bytes survive between requests without any
	daemon. Writers that arrive while no holder is alive block in open()
	until the next request. Bytes are lost only when data sits unread
	through 10+ s of no device access.

	Without these files (old ids), fall back to echoing the payload + 0x72.
*/
$from_fifo = "$keys_dir/from_$id";
$to_fifo   = "$keys_dir/to_$id";
$bridged = file_exists($from_fifo) && file_exists($to_fifo);
if ($bridged) {
	$fh = @fopen($from_fifo, "r+");	/* r+ never blocks on a FIFO */
	if ($fh) {
		stream_set_blocking($fh, false);
		$s = "";
		foreach ($out as $c)
			$s .= chr($c);
		@fwrite($fh, $s);
		fclose($fh);
	}
}

$resp_hex = "";
if ($wantreply) {
	if ($bridged) {
		$s = (string)shell_exec("sh " . escapeshellarg(__DIR__ . "/to-drain.sh")
		                        . " " . escapeshellarg($to_fifo));
		$reply_src = array();
		for ($i=0; $i<strlen($s); $i++)
			$reply_src[] = ord(substr($s, $i, 1));
		$out = $reply_src;
	} else {
		$out[] = 0x72;	/* response marker (echo mode) */
	}

	$c = new chacha20();
	$reply    = $c->crypt($out, $key, $nonce);
	$replytag = c20p1305_mac(array(), $reply, $key, $nonce);

	foreach ($nonce as $c)    $resp_hex .= sprintf("%02x", $c);
	foreach ($reply as $c)    $resp_hex .= sprintf("%02x", $c);
	foreach ($replytag as $c) $resp_hex .= sprintf("%02x", $c);
}

/* Persist <request, response> atomically (tmp + rename). Same-id concurrency
   is assumed not to happen — a device only retries serially. For no-reply
   (flagged) requests the stored response is empty, so a retry of the same
   nonce prints nothing, matching the original exchange. */
$tmp = "$state_file." . getmypid();
file_put_contents($tmp, "$req_hex\t$resp_hex");
rename($tmp, $state_file);

if ($resp_hex !== "")
	print "key0c20=$resp_hex\n\n";
