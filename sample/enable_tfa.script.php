<?php
    declare(strict_types=1);
    require_once('include.php');
    $tfaInfo = SimpleAuth::createTfaCode(SimpleAuth::username());
    $qr = $tfaInfo->qr;
    header('location:qr.php?qr='.urlencode($qr));