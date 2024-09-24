<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

if(!SimpleAuth::user_id()) {
	header('location:.');
	exit;
}

$body = design('get user_id');
$body->el('a',['href'=>'.'])->te('Back');

$form = $body->el('form',['method'=>'post','action'=>'get_user_id.script.php']);
$form->el('label')->te('Username');
$form->el('input',['name'=>'username','required','value'=>empty($_GET['username']) ? '' : $_GET['username']]);
$form->el('br');

if(isset($_GET['error'])) {
	$form->el('pre',['style'=>'color:red;'])->te($_GET['error']);
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Get');
