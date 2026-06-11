<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

namespace TRP\SimpleAuth;

Class HttpService {
	public static function www_authenticate(string $realm = 'SimpleAuth Login') : void {
		if(SimpleAuthSession::user_id()) {
			return;
		}
		if(empty($_SERVER['PHP_AUTH_USER']) || empty($_SERVER['PHP_AUTH_PW'])) {
			self::www_dialog($realm);
		}
		else {
			try {
				SimpleAuthSession::login($_SERVER['PHP_AUTH_USER'],$_SERVER['PHP_AUTH_PW'], false);
			}
			catch(\Exception $e){
				self::www_dialog($realm,ErrorHandler::error_string($e->getMessage()));
			}
		}
	}
	public static function www_dialog(string $realm, string $message = 'Unauthorized') : void {
		header('WWW-Authenticate: Basic realm="'.$realm.'", charset="UTF-8"');
		header('HTTP/1.1 401 '.$message);
		echo $message;
		exit;
	}
}
