<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

$body = design('index');

if(isset($_GET['message'])) {
	$body->el('pre',['style'=>'color:green;'])->te($_GET['message']);
	$body->el('br');
}

if(!SimpleAuth::user_id()) {
	$body->el('h3')->te('Not logged in!');
	$body->el('a',['href'=>'login.php'])->te('Login');
	$body->el('br');
	$body->el('a',['href'=>'create.php'])->te('Create user');
	$body->el('br');
	$body->el('a',['href'=>'confirmation.php'])->te('Confirm user');
}
else {
	$body->el('h3')->te('user_id: '.SimpleAuth::user_id());
	$body->el('a',['href'=>'change_password.php'])->te('Change password');
	$body->el('br');
	$body->el('a',['href'=>'get_user_id.php'])->te('Get other user_id');
	$body->el('br');
	$body->el('a',['href'=>'logout.script.php'])->te('Logout');
}

$ul = $body->el('ul');

if(true) {
	$ul->el('li')->te('guest access');
}

if(SimpleAuth::access('editor')) {
	$ul->el('li')->te('editor access');
}

if(SimpleAuth::access('admin')) {
	$ul->el('li')->te('admin access');
}

if(SimpleAuth::access('other')) {
	$ul->el('li')->te('other access');
}
