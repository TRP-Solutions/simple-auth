<?php
require_once('include.php');

$doc = new HealHTML();
list($head,$head) = $doc->html('simple-auth :: index');

if(!$auth->user_id()) {
	$doc->el('h3')->te('Not logged in!');
	$doc->a('login.php','Login');
}
else {
	$doc->el('h3')->te('user_id: '.$auth->user_id());
	$doc->a('logout.script.php','Logout');
}

$ul = $doc->el('ul');

if(true) {
	$ul->el('li')->te('guest access');
}

if($auth->access('editor')) {
	$ul->el('li')->te('editor access');
}

if($auth->access('admin')) {
	$ul->el('li')->te('admin access');
}

if($auth->access('other')) {
	$ul->el('li')->te('other access');
}

echo $doc;