<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

if(!SimpleAuth::user_id()) {
	header('location:.');
	exit;
}

$body = design('change password');
$body->el('a',['href'=>'.'])->te('Back');

$form = $body->el('form',['method'=>'post','action'=>'change_password.script.php']);
$form->el('label')->te('Current password');
$form->el('input',['name'=>'password_current','required','type'=>'password']);
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

$form->el('button',['type'=>'submit'])->te('Change');
