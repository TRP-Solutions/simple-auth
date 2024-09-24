<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
	if(!empty($_POST['confirmation'])) {
		$cr_result = SimpleAuth::create_user($_POST['username']);
		$ha_result = SimpleAuth::confirm_hash($cr_result->user_id);
		// Don't use GET variables in production code.
		header('location:confirmation.php?confirmation='.urlencode($ha_result->confirmation));
	}
	else {
		SimpleAuth::verify_password($_POST['password'],$_POST['password_confirm']);
		$result = SimpleAuth::create_user($_POST['username']);

		SimpleAuth::change_password($_POST['password'],$result->user_id);
		header('location:.?message='.urlencode('Ready to login'));
	}
}
catch(\Exception $e) {
	$msg = SimpleAuth::error_string($e->getMessage());
	header('location:create.php?error='.urlencode($msg).'&username='.$_POST['username']);
}
