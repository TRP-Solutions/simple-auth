<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

$result = SimpleAuth::create_user($_POST['username'],$_POST['password'],$_POST['password_confirm'],!empty($_POST['confirmation']));

if(isset($result->error)) {
	header('location:create.php?error='.$result->error.'&username='.$_POST['username']);
}
else {
	if(!empty($_POST['confirmation'])) {
		// Don't use GET variables in production code.
		header('location:confirmation.php?confirmation='.urlencode($result->confirmation));
	}
	else {
		header('location:index.php');
	}
}
