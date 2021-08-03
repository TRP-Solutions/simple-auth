<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

try {
	SimpleAuth::change_password($_POST['password'],null,$_POST['password_confirm'],$_POST['password_current']);
	header('location:.');
}
catch(Exception $e) {
	$msg = SimpleAuth::error_string($e->getMessage());
	header('location:change_password.php?error='.urlencode($msg));
}
