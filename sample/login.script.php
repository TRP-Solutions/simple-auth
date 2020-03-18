<?php
require_once('include.php');

$result = $auth->login($_POST['username'],$_POST['password'],$_POST['autologin']);

if(isset($result->error)) {
	header('location:login.php?error='.$result->error.'&username='.$_POST['username']);
}
else {
	header('location:index.php');
}