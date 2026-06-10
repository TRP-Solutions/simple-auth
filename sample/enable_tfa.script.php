<?php
    declare(strict_types=1);
    require_once('include.php');
    try {
        $qr = \TRP\SimpleAuth\TfaService::create_tfa(new \TRP\SimpleAuth\SimpleAuthManagement(\TRP\SimpleAuth\SimpleAuthSession::user_id()));
        header('location:qr.php?qr='.urlencode($qr));
    }
    catch(\Exception $e) {
        $msg = \TRP\SimpleAuth\ErrorHandler::error_string($e->getMessage());
        header('location:.?error='.urlencode($msg));
    }