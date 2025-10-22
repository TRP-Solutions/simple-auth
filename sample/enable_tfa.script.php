<?php
    declare(strict_types=1);
    require_once('include.php');
    $tfaInfo = SimpleAuth::create_tfa_code(SimpleAuth::username());
    $qr = $tfaInfo->qr;
    header('location:qr.php?qr='.urlencode($qr));