<?php

declare(strict_types=1);
require_once('include.php');

try {
    if(!SimpleAuth::validate_tfa_code($_POST['username'],$_POST['totp'])){
        header('location:tfa.php?error='.urlencode('2fa code is invalid').'&username='.$_POST['username']);
        return;
    }
    SimpleAuth::login_with_username($_POST['username']);
    header('location:.');
}
catch(\Exception $e) {
    $msg = SimpleAuth::error_string($e->getMessage());
    header('location:login.php?error='.urlencode($msg).'&username='.$_POST['username']);
}