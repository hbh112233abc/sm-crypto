<?php
require __DIR__ . '/../vendor/autoload.php';

list($priKey, $pubKey) = generateKeyPairHex();

var_dump('private key:', $priKey);
var_dump('public key:', $pubKey);
