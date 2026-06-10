<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
	\TRP\SimpleAuth\PasswordEncoder::verify($_POST['password'],$_POST['password_confirm']);
	$user_id = \TRP\SimpleAuth\SimpleAuthManagement::create($_POST['username']);

	$ha_result = \TRP\SimpleAuth\SimpleAuthSession::confirm_hash($user_id);

	// Don't use GET variables in production code.
	header('location:confirmation.php?confirmation='.urlencode($ha_result->confirmation));
}
catch(\Exception $e) {
    error_log($e->getTraceAsString());
	$msg = \TRP\SimpleAuth\ErrorHandler::error_string($e->getMessage());
	header('location:create.php?error='.urlencode($msg).'&username='.$_POST['username']);
}
