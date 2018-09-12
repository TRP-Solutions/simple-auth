<?php
require_once('include.php');

$result = $auth->login($_POST['username'],$_POST['password']);

if(isset($result->error)) {
	header('location:login.php?error='.$result->error.'&username='.$_POST['username']);
}
else {
	$auth->add_access('access');
	header('location:index.php');
}
?>