<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('../../git_heal-document/lib/HealHTML.php'); // https://github.com/TRP-Solutions/heal-document
require_once('../lib/SimpleAuth.php');

$auth = new SimpleAuth([
	'db_user' => 'root',
	'db_pass' => 'mysqlnimda',
	'db_base' => 'simpleauth',
	'onlogin' => function($auth){$auth->add_access('other');},
	'autologin_secure' => false
]);