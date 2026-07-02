<?php

declare(strict_types=1);
require_once('include.php');

try {
	\TRP\SimpleAuth\Session::validate_tfa_code($_POST['username'],$_POST['totp'], true);
    header('location:.');
}
catch(\Exception $e) {
    $msg = \TRP\SimpleAuth\ErrorHandler::error_string($e->getMessage());
    header('location:tfa.php?error='.urlencode($msg).'&username='.$_POST['username']);
}