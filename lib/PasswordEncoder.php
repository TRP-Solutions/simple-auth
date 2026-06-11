<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

namespace TRP\SimpleAuth;

Class PasswordEncoder {
	public static function encode(string $password) : string {
		return password_hash($password, PASSWORD_DEFAULT);
	}

	public static function matches(string $raw, string $hash) : bool {
		return password_verify($raw, $hash);
	}

	public static function verify(string $password, string $password_confirm) : void {
		if(!$password){
			throw new \Exception('PASSWORD_NOTSET');
		}
		if($password_confirm && $password!=$password_confirm){
			throw new \Exception('PASSWORD_NOMATCH');
		}
	}
}
