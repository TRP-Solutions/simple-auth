<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

try {
	\TRP\SimpleAuth\PasswordEncoder::verify($_POST['password'],$_POST['password_confirm']);
	$user_id = \TRP\SimpleAuth\SimpleAuthSession::confirm_verify($_POST['confirmation']);
	new \TRP\SimpleAuth\SimpleAuthManagement($user_id)->set_password($_POST['password']);

    if(!empty($_POST['qr'])){
        header('location:qr.php?qr='.urlencode($_POST['qr']));
        return;
    }
    header('location:.');
}
catch(\Exception $e) {
	$msg = \TRP\SimpleAuth\ErrorHandler::error_string($e->getMessage());
    if(!empty($_POST['qr'])){
        header('location:confirmation.php?error='.urlencode($msg).'&qr='.urlencode($_POST['qr']).'&confirmation='.urlencode($_POST['confirmation']));
        return;
    }
    header('location:confirmation.php?error='.urlencode($msg).'&confirmation='.urlencode($_POST['confirmation']));
}

