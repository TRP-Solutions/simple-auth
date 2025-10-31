<?php

declare(strict_types=1);
require_once('include.php');

try {
	SimpleAuth::login_with_tfa_code($_POST['username'],$_POST['totp']);
    header('location:.');
}
catch(\Exception $e) {
    $msg = SimpleAuth::error_string($e->getMessage());
    header('location:tfa.php?error='.urlencode($msg).'&username='.$_POST['username']);
}