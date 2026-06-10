<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
	new \TRP\SimpleAuth\SimpleAuthManagement(\TRP\SimpleAuth\SimpleAuthSession::user_id())->update_password($_POST['password'], $_POST['password_current'], $_POST['password_confirm']);
	header('location:.?message='.urlencode('Password changed'));
}
catch(\Exception $e) {
	$msg = \TRP\SimpleAuth\ErrorHandler::error_string($e->getMessage());
	header('location:change_password.php?error='.urlencode($msg));
}
