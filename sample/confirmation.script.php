<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

try {
	SimpleAuth::verify_password($_POST['password'],$_POST['password_confirm']);
	$result = SimpleAuth::confirm_verify($_POST['confirmation']);
	SimpleAuth::change_password($_POST['password'],$result->user_id);

	header('location:.?message='.urlencode('Ready to login'));
}
catch(\Exception $e) {
	$msg = SimpleAuth::error_string($e->getMessage());
	header('location:confirmation.php?error='.urlencode($msg).'&confirmation='.urlencode($_POST['confirmation']));
}

