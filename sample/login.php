<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

if(SimpleAuth::user_id()) {
	header('location:.');
	exit;
}

$body = design('login');
$body->el('a',['href'=>'.'])->te('Back');

$form = $body->el('form',['method'=>'post','action'=>'login.script.php']);
$form->el('label')->te('Username');
$form->el('input',['name'=>'username','required','value'=>empty($_GET['username']) ? '' : $_GET['username']]);
$form->te(' default: johndoe');
$form->el('br');
$form->el('label')->te('Password');
$form->el('input',['name'=>'password','required','type'=>'password']);
$form->te(' default: Pa55w0rd');
$form->el('br');
$form->el('label')->te('Autologin');
$form->el('input',['name'=>'autologin','type'=>'checkbox']);
$form->el('br');

if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te($_GET['error']);
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Login');
