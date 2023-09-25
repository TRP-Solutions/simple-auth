<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
require_once('include.php');
SimpleAuth::www_authenticate();

header('Content-Type: text/plain');
echo 'user_id: '.SimpleAuth::user_id().PHP_EOL;
