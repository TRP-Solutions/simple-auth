<?php
    declare(strict_types=1);
    require_once('include.php');
    SimpleAuth::delete_tfa_code((string)SimpleAuth::user_id());
    header('location:.');