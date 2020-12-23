<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

$result = SimpleAuth::login($_POST['username'],$_POST['password'],$_POST['autologin']);

if(isset($result->error)) {
	header('location:login.php?error='.$result->error.'&username='.$_POST['username']);
}
else {
	header('location:index.php');
}
