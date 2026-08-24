<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

\TRP\SimpleAuth\Session::www_authenticate();

header('Content-Type: text/plain');
echo 'user_id: '.\TRP\SimpleAuth\Session::user_id().PHP_EOL;
