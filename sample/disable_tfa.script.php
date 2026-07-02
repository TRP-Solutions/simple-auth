<?php
    declare(strict_types=1);
    require_once('include.php');
	\TRP\SimpleAuth\TfaService::delete_tfa(new \TRP\SimpleAuth\Management(\TRP\SimpleAuth\Session::user_id()));
	header('location:.');