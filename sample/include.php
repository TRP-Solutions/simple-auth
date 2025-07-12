<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('../../heal-document/lib/HealDocument.php'); // https://github.com/TRP-Solutions/heal-document
require_once('design.php');
require_once('../lib/SimpleAuth.php');

SimpleAuth::configure([
	'db_user' => 'simpleauth',
	'db_pass' => 'mysqlnimda',
	'db_base' => 'simpleauth',
	'onlogin' => function(){SimpleAuth::add_access('other');},
	'autologin_secure' => false
]);
