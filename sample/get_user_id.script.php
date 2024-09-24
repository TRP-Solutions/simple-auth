<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

if(!SimpleAuth::user_id()) {
	header('location:.');
	exit;
}

try {
	$user_id = SimpleAuth::get_user_id($_POST['username']);
	header('location:.?message='.urlencode("user_id for ($_POST[username]): ".$user_id));
}
catch(\Exception $e) {
	$msg = SimpleAuth::error_string($e->getMessage());
	header('location:get_user_id.php?error='.urlencode($msg).'&username='.$_POST['username']);
}
