<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('../../heal-document/lib/HealDocument.php'); // https://github.com/TRP-Solutions/heal-document
require_once('design.php');
require_once('../lib/require_all.php');

$db = new mysqli(
	'localhost', // host
	'admin',      // username
	'admin',          // password
	'simpleauth' // database
);

if ($db->connect_error) {
	throw new RuntimeException(
		'Database connection failed: ' . $db->connect_error
	);
}

\TRP\SimpleAuth\Config::configure(
	db_conn: $db,
	on_login: function(){\TRP\SimpleAuth\SimpleAuthSession::add_access('other');},
	db_pfix: "auth_"
);
