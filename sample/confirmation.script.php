<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');

$result = SimpleAuth::confirm($_POST['confirmation']);

if(isset($result->error)) {
	header('location:confirmation.php?error='.$result->error.'&confirmation='.$_POST['confirmation']);
}
else {
	header('location:index.php');
}
