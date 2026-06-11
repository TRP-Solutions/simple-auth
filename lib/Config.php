<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

namespace TRP\SimpleAuth;

Class Config{
	public static \mysqli $db_conn;
	public static string $db_pfix;
	public static string $session_var;
	public static int $lifetime;
	public static string $cookie_pfix;
	public static string $cookie_path;
	public static bool $cookie_secure;
	public static int $autologin_expire;
	public static int $token_bytes;
	public static string $charset;
	public static ?\Closure $on_login;
	public static string $tfa_issuer;
	public static array $require_tfa;

	static function configure(
		\mysqli $db_conn,
		string $db_pfix = 'auth_',
		string $session_var = 'auth',
		int $lifetime = 0,
		string $cookie_pfix = 'auth_',
		string $cookie_path = '',
		bool $cookie_secure = false,
		int $autologin_expire = 2592000,
		int $token_bytes = 32,
		string $charset = 'utf8mb4',
		?\Closure $on_login = null,
		string $tfa_issuer = 'SimpleAuth',
		array $require_tfa = []
	): void {
		self::$db_conn = $db_conn;
		self::$db_pfix = $db_pfix;
		self::$session_var = $session_var;
		self::$lifetime = $lifetime;
		self::$cookie_pfix = $cookie_pfix;
		self::$cookie_path = $cookie_path;
		self::$cookie_secure = $cookie_secure;
		self::$autologin_expire = $autologin_expire;
		self::$token_bytes = $token_bytes;
		self::$charset = $charset;
		self::$on_login = $on_login;
		self::$tfa_issuer = $tfa_issuer;
		self::$require_tfa = $require_tfa;

		if(self::$lifetime){
			ini_set('session.gc_maxlifetime', self::$lifetime);
		}

		session_set_cookie_params(self::$lifetime, self::$cookie_path, null, self::$cookie_secure);
		session_start();
		if(self::$lifetime) {
			setcookie(session_name(), session_id(), time()+self::$lifetime, self::$cookie_path, null, self::$cookie_secure);
		}

		SimpleAuthSession::load_session();

	}
}
