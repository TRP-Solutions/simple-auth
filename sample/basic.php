<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);
require_once('include.php');

\TRP\SimpleAuth\HttpService::www_authenticate();

header('Content-Type: text/plain');
echo 'user_id: '.\TRP\SimpleAuth\SimpleAuthSession::user_id().PHP_EOL;
