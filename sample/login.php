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
list($head,$body) = $doc->html('simple-auth :: login');

$form = $body->form('login.script.php','post');
$form->label('Username','username');
$form->input('username',empty($_GET['username']) ? '' : $_GET['username'])->at(['required'=>null]);
$form->te(' default: johndoe');
$form->el('br');
$form->label('Password','password');
$form->password('password')->at(['required'=>null]);
$form->te(' default: passw0rd');
$form->el('br');
$form->label('Autologin','autologin');
$form->checkbox('autologin');
$form->el('br');

if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te(SimpleAuth::error_string($_GET['error']));
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Login');

echo $doc;
