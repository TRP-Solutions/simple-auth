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

$doc = new HealHTML();
list($head,$body) = $doc->html('simple-auth :: confirmation');
$body->el('h2')->te('confirmation');
$body->a('.','Back');

$body->p('Copy-paste confirmation string to confirm user. Deliver via alternative method (E-mail, SMS) in production code:');

$body->el('pre',['style'=>'color:red;'])->te(!empty($_GET['confirmation']) ? $_GET['confirmation'] : '');
$body->el('br');

$form = $body->form('confirmation.script.php','post');
$form->label('Confirmation','confirmation');
$form->input('confirmation')->at(['required']);
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

$form->el('button',['type'=>'submit'])->te('Confirm');

echo $doc;
