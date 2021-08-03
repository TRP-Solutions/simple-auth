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
list($head,$body) = $doc->html('simple-auth :: login');
$body->el('h2')->te('login');
$body->a('.','Back');

$form = $body->form('get_user_id.script.php','post');
$form->label('Username','username');
$form->input('username',empty($_GET['username']) ? '' : $_GET['username'])->at(['required']);
$form->el('br');

if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te($_GET['error']);
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Get');

echo $doc;
