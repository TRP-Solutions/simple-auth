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
list($head,$body) = $doc->html('simple-auth :: confirmation');

$body->p('Copy-paste confirmation string to confirm user. Deliver via alternative method (E-mail, SMS) in production code:');

$body->el('pre',['style'=>'color:red;'])->te($_GET['confirmation']);
$body->el('br');

$form = $body->form('confirmation.script.php','post');
$form->label('Confirmation','confirmation');
$form->input('confirmation')->at(['required'=>null]);
$form->el('br');

if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te(SimpleAuth::error_string($_GET['error']));
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Confirm');

echo $doc;
