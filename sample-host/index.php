<?php

/*
	Single file chacha20poly1305 https://github.com/paijp/single-file-chacha20poly1305
	
	License: MIT or PUBLIC DOMAIN.
*/

require("c20p1305.php");

$s = @$_GET["key0c20"];
file_put_contents("log.txt", date("ymd_His>").$s."\n", FILE_APPEND);
$a = array();
$bin = hex2bin($s);
for ($i=0; $i<strlen($bin); $i++)
	$a[] = ord(substr($bin, $i, 1));
if (count($a) < 28)
	die();

$key = array(
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  
	0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0
);
$nonce = array_slice($a, 0, 12);
$body = array_slice($a, 12, count($a) - 28);
$tag = array_slice($a, count($a) - 16);

cmp_array($tag, c20p1305_mac(array(), $body, $key, $nonce));
$c = new chacha20();
$out = $c->crypt($body, $key, $nonce);
$s = "";
foreach ($out as $c)
	$s .= chr($c);

file_put_contents("log.txt", date("ymd_His>").$s."\n", FILE_APPEND);

if (($nonce[11] & 1))
	die();

$nonce[11] |= 1;
#print "reply.\n";

$out[] = 0x72;

$c = new chacha20();
$reply = $c->crypt($out, $key, $nonce);
$replytag = c20p1305_mac(array(), $reply, $key, $nonce);
$s = "";
foreach ($nonce as $c)
	$s .= sprintf("%02x", $c);
foreach ($reply as $c)
	$s .= sprintf("%02x", $c);
foreach ($replytag as $c)
	$s .= sprintf("%02x", $c);
file_put_contents("log.txt", date("ymd_His<").$s."\n", FILE_APPEND);
print "key0c20={$s}\n\n";
