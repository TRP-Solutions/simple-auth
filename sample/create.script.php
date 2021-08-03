<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

try {
	$result = SimpleAuth::create_user($_POST['username'],$_POST['password'],false,!empty($_POST['confirmation']));
	if(!empty($_POST['confirmation'])) {
		// Don't use GET variables in production code.
		header('location:confirmation.php?confirmation='.urlencode($result->confirmation));
	}
	else {
		header('location:.');
	}
}
catch(Exception $e) {
	$msg = SimpleAuth::error_string($e->getMessage());
	header('location:create.php?error='.urlencode($msg).'&username='.$_POST['username']);
}
