<?php
require_once('include.php');

if($auth->user_id()) {
	header('location:index.php');
	exit;
}

$doc = new HealHTML();
list($head,$head) = $doc->html('simple-auth :: login');

$form = $head->form('login.script.php','post');
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
	$form->el('pre',['style'=>'color:red;'])->te($auth->error_string($_GET['error']));
	$form->el('br');
}

$form->el('button',['type'=>'submit'])->te('Login');

echo $doc;
?>