<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
	\TRP\SimpleAuth\Management::disable(\TRP\SimpleAuth\Session::user_id());
}
catch(\Exception $e) {
	$msg = \TRP\SimpleAuth\ErrorHandler::error_string($e->getMessage());
	echo $msg;
	exit;
}

\TRP\SimpleAuth\Session::logout();
header('location:.');
