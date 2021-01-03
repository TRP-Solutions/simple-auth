<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

if(SimpleAuth::user_id()) {
	header('location:index.php');
	exit;
}

$doc = new HealHTML();
list($head,$body) = $doc->html('simple-auth :: create user');

$form = $body->form('create.script.php','post');
$form->label('Username','username');
$form->input('username',empty($_GET['username']) ? '' : $_GET['username'])->at(['required'=>null]);
$form->el('br');
$form->label('Password','password');
$form->password('password')->at(['required'=>null]);
$form->el('br');
$form->label('Repeat Password','password_confirm');
$form->password('password_confirm')->at(['required'=>null]);
$form->el('br');
$form->label('Use confirmation','confirmation');
$form->checkbox('confirmation');
$form->el('br');

if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te($auth->error_string($_GET['error']));
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Login');

echo $doc;
