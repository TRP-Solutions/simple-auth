<?php

declare(strict_types=1);
require_once('include.php');

try {
    if(!SimpleAuth::validateTfaCode($_POST['username'],$_POST['totp'])){
        header('location:tfa.php?error='.urlencode('2fa code is invalid').'&username='.$_POST['username']);
        return;
    }
    SimpleAuth::loginWithUsername($_POST['username']);
    header('location:.');
}
catch(\Exception $e) {
    $msg = SimpleAuth::error_string($e->getMessage());
    header('location:login.php?error='.urlencode($msg).'&username='.$_POST['username']);
}