<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

$doc = new HealHTML();
list($head,$body) = $doc->html('simple-auth :: index');
$body->el('h2')->te('index');

if(!SimpleAuth::user_id()) {
	$body->el('h3')->te('Not logged in!');
	$body->a('login.php','Login');
	$body->el('br');
	$body->a('create.php','Create user');
	$body->el('br');
	$body->a('confirmation.php','Confirm user');
}
else {
	$body->el('h3')->te('user_id: '.SimpleAuth::user_id());
	$body->a('change_password.php','Change password');
	$body->el('br');
	$body->a('logout.script.php','Logout');
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

echo $doc;
