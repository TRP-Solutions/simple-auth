<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
	SimpleAuth::login($_POST['username'],$_POST['password'],!empty($_POST['autologin']));
	header('location:.');
}
catch(\Exception $e) {
	$msg = SimpleAuth::error_string($e->getMessage());
	header('location:login.php?error='.urlencode($msg).'&username='.$_POST['username']);
}
