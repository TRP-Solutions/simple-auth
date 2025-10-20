<?php
    declare(strict_types=1);
    require_once('include.php');
    SimpleAuth::deleteTfaCode(SimpleAuth::username());
    header('location:.');