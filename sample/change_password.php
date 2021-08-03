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

$doc = new HealHTML();
list($head,$body) = $doc->html('simple-auth :: change password');
$body->el('h2')->te('change password');
$body->a('.','Back');

$form = $body->form('change_password.script.php','post');
$form->label('Current password','password_current');
$form->password('password_current')->at(['required']);
$form->el('br');
$form->label('Password','password');
$form->password('password')->at(['required']);
$form->el('br');
$form->label('Repeat Password','password_confirm');
$form->password('password_confirm')->at(['required']);
$form->el('br');

if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te($_GET['error']);
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Change');

echo $doc;
