<?php
require_once('../../git_heal-document/lib/HealHTML.php'); // https://github.com/TRP-Solutions/heal-document
require_once('../lib/SimpleAuth.php');

$auth = new SimpleAuth([
	'db_user' => 'my_user',
	'db_pass' => 'my_password',
	'db_base' => 'my_db'
]);
?>