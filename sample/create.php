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

$body = design('create user');
$body->el('a',['href'=>'.'])->te('Back');

$form = $body->el('form',['method'=>'post','action'=>'create.script.php']);
$form->el('label')->te('Username');
$form->el('input',['name'=>'username','required']);
$form->el('br');
$form->el('label')->te('Password');
$form->el('input',['name'=>'password','id'=>'password','required','type'=>'password']);
$form->el('br');
$form->el('label')->te('Repeat Password');
$form->el('input',['name'=>'password_confirm','id'=>'password_confirm','required','type'=>'password']);
$form->el('br');
$form->el('label')->te('Use confirmation');

$js = "document.getElementById('password').disabled = this.checked;";
$js .= "document.getElementById('password_confirm').disabled = this.checked;";

$form->el('input',['name'=>'confirmation','type'=>'checkbox','onchange'=>$js]);
$form->el('br');

if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te($_GET['error']);
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Login');
