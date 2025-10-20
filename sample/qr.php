<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

$body = design('2fa qr code');
$body->el('img', ['src'=>$_GET['qr']]);
$body->el('br');
$body->el('a',['href'=>'.'])->te('Home');
