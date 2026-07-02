<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
    if(!$_POST['password']){
        throw new \Exception('PASSWORD_NOTSET');
    }
    if($_POST['password_confirm'] && $_POST['password']!=$_POST['password_confirm']){
        throw new \Exception('PASSWORD_NOMATCH');
    }
	$user_id = \TRP\SimpleAuth\Management::create($_POST['username']);

	$ha_result = \TRP\SimpleAuth\Session::confirm_hash($user_id);

	// Don't use GET variables in production code.
	header('location:confirmation.php?confirmation='.urlencode($ha_result->confirmation));
}
catch(\Exception $e) {
    error_log($e->getTraceAsString());
	$msg = \TRP\SimpleAuth\ErrorHandler::error_string($e->getMessage());
	header('location:create.php?error='.urlencode($msg).'&username='.$_POST['username']);
}
