<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

if(SimpleAuth::user_id()) {
	header('location:.');
	exit;
}

$body = design('confirmation');
$body->el('a',['href'=>'.'])->te('Back');

$body->el('p')->te('Copy-paste confirmation string to confirm user. Deliver via alternative method (E-mail, SMS) in production code:');

$body->el('pre',['style'=>'color:red;'])->te(!empty($_GET['confirmation']) ? $_GET['confirmation'] : '');
$body->el('br');

$form = $body->el('form',['method'=>'post','action'=>'confirmation.script.php']);
$form->el('label')->te('Confirmation');
$form->el('input',['name'=>'confirmation','required']);
$form->el('br');
$form->el('label')->te('Password');
$form->el('input',['name'=>'password','required','type'=>'password']);
$form->el('br');
$form->el('label')->te('Repeat Password');
$form->el('input',['name'=>'password_confirm','required','type'=>'password']);
$form->el('br');


if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te($_GET['error']);
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Confirm');
