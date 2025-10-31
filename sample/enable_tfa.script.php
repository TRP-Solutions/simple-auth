<?php
    declare(strict_types=1);
    require_once('include.php');
    try {
        $tfaInfo = SimpleAuth::create_tfa_code((string)SimpleAuth::user_id());
        $qr = $tfaInfo->qr;
        header('location:qr.php?qr='.urlencode($qr));
    }
    catch(\Exception $e) {
        $msg = SimpleAuth::error_string($e->getMessage());
        header('location:.?error='.urlencode($msg));
    }