<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
	SimpleAuth::disable(SimpleAuth::user_id());
}
catch(\Exception $e) {
	$msg = SimpleAuth::error_string($e->getMessage());
	echo $msg;
	exit;
}

SimpleAuth::logout();
header('location:.');
