<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

namespace TRP\SimpleAuth;

Class SimpleAuthSession {
	private static bool $has_loaded_session = false;
	private static int $user_id = 0;
	private static array $access = [];
	public static bool $has_tfa = false;
	public static function login(string $username, string $password, bool $auto_login) : bool {
		if (!$username) { throw new \Exception('USERNAME_NOTSET'); }
		if (!$password) { throw new \Exception('PASSWORD_NOTSET'); }

		$username = trim(Config::$db_conn->real_escape_string($username));
		$table = Config::$db_pfix . 'user';

		$sql = "SELECT `id`,`password`,`tfa_status` FROM `$table` WHERE `username`='$username'";
		$query = Config::$db_conn->query($sql);
		if ($query->num_rows !== 1) {
			throw new \Exception('USERNAME_UNKNOWN');
		}

		$rs = $query->fetch_object();

		if (empty($rs->password)) {
			throw new \Exception('USER_NOT_ACTIVE');
		}
		if (!password_verify($password, $rs->password)) {
			throw new \Exception('PASSWORD_WRONG');
		}
		if ($rs->tfa_status == 'active') {
			$user_id  = (int)$rs->id;
			$table = Config::$db_pfix . 'pending';
			$sql = "INSERT INTO `$table` (user_id, username, expires)
			VALUES ($user_id, '$username', DATE_ADD(NOW(), INTERVAL 5 MINUTE))
			ON DUPLICATE KEY UPDATE
				username = VALUES(username),
				expires = VALUES(expires)";

			Config::$db_conn->query($sql);
			return false;
		}

		self::$user_id = (int)$rs->id;
		self::update_access();
		self::save_session();
		self::$has_tfa = false;
		if ($auto_login) self::write_autologin_cookie();
		self::$has_loaded_session = true;

		self::login_successful();
		return true;
	}

	public static function validate_tfa_code(string $username, string $tfa_code, bool $auto_login) : bool {
		$username = trim(Config::$db_conn->real_escape_string($username));

		$table = Config::$db_pfix . 'user';
		$sql = "SELECT `id` FROM `$table` WHERE `username`='$username'";
		$query = Config::$db_conn->query($sql);
		$rs = $query->fetch_object();
		$userId = (int)$rs->id;

		$table = Config::$db_pfix . 'pending';
		$sql = "SELECT `expires` < NOW() as `expired` FROM `$table` WHERE `user_id`='$userId'";
		$query = Config::$db_conn->query($sql);
		if ($query->num_rows !== 1 || $query->fetch_object()->expired) {
			throw new \Exception('TFA_NOT_REQUESTED');
		}

		if(!TfaService::validate_tfa_code(new SimpleAuthManagement($userId), $tfa_code)) {
			throw new \Exception('TFA_INVALID');
		}

		$sql = "DELETE FROM `$table` WHERE `user_id`='$userId'";
		Config::$db_conn->query($sql);

		self::$user_id = $userId;
		self::$has_tfa = true;
		self::update_access();
		self::save_session();
		if ($auto_login) self::write_autologin_cookie();
		self::login_successful();
		return true;
	}

	public static function logout() : void {
		unset($_SESSION[Config::$session_var]);
		self::$has_loaded_session = false;
		self::$user_id = 0;
		self::$access = [];
		self::$has_tfa = false;
		self::delete_autologin_cookie();
	}

	public static function load_session() : void {
		if(isset($_SESSION[Config::$session_var])){
			$json = json_decode($_SESSION[Config::$session_var]);
			self::$user_id = $json->user_id;
			self::$access = $json->access;
			self::$has_tfa = $json->has_tfa;
			self::$has_loaded_session = true;
		} elseif(isset($_COOKIE[Config::$cookie_pfix.'autologin'])){
			$token = Config::$db_conn->real_escape_string($_COOKIE[Config::$cookie_pfix.'autologin']);
			$table = Config::$db_pfix.'token';
			$sql = "SELECT user_id,token,expires<=NOW() as expired FROM `$table` WHERE token='$token'";
			$query = Config::$db_conn->query($sql);
			if($query->num_rows!=1){
				self::delete_autologin_cookie();
				return;
			}
			$rs = $query->fetch_object();
			if($rs->expired){
				self::delete_autologin_cookie();
				$sql = "DELETE FROM `$table` WHERE expires<NOW()";
				Config::$db_conn->query($sql);
				return;
			}
			self::$user_id = (int) $rs->user_id;
			self::write_autologin_cookie();
			self::update_access();
			self::save_session();
			self::$has_loaded_session = true;

			self::login_successful();
		}
	}

	public static function user_id() : int {
		return self::$user_id;
	}

	public static function has_tfa() : bool {
		return self::$has_tfa;
	}

	public static function access(string ...$access): bool
	{
		foreach ($access as $permission) {
			if (!in_array($permission, self::$access, true)) {
				return false;
			}
		}

		return true;
	}

	public static function update_access() : void {
		if(self::$user_id != 0){
			$table = Config::$db_pfix.'access';
			$user_id = self::$user_id;
			$sql = "SELECT `permission` FROM `$table` WHERE `user_id`='$user_id'";
			$query = Config::$db_conn->query($sql);
			while($rs = $query->fetch_object()){
				if(in_array($rs->permission, Config::$require_tfa, true) && !self::$has_tfa) continue;

				self::add_access($rs->permission,false);
			}
		}
	}

	public static function save_session() : void {
		$json = json_encode([
			'user_id' => self::$user_id,
			'access' => self::$access,
			'has_tfa' => self::$has_tfa
		]);

		$_SESSION[Config::$session_var] = $json;
	}

	// Maybe move this into SimpleAuthManagement
	public static function confirm_hash(int $user_id) : object {
		$table = Config::$db_pfix.'user';
		$sql = "SELECT `username` FROM `$table` WHERE `id`='$user_id'";
		$query = Config::$db_conn->query($sql);
		if($query->num_rows!=1){
			throw new \Exception('INVALID_USERID');
		}
		$rs = $query->fetch_object();

		$token = self::generate_secure_token();
		$token_sql = password_hash($token, PASSWORD_DEFAULT);
		$confirmation = base64_encode($rs->username.':'.$token);

		$sql = "UPDATE `$table` SET `confirmation`='$token_sql' WHERE `id`='$user_id'";
		Config::$db_conn->query($sql);

		return (object) ['confirmation'=>$confirmation];
	}

	// Maybe move this into SimpleAuthManagement
	public static function confirm_verify(string $confirmation) : int {
		$str = base64_decode($confirmation);
		if($str===false){
			throw new \Exception('CONFIRMATION_INVALID');
		}
		$array = explode(':',$str);
		if(sizeof($array)!==2){
			throw new \Exception('CONFIRMATION_INVALID');
		}
		list($username,$token) = $array;

		$sql_username = trim(Config::$db_conn->real_escape_string($username));
		$table = Config::$db_pfix.'user';
		$sql = "SELECT `id`,`confirmation` FROM `$table` WHERE `username`='$sql_username'";
		$query = Config::$db_conn->query($sql);
		if($query->num_rows!=1){
			throw new \Exception('USERNAME_UNKNOWN');
		}

		$rs = $query->fetch_object();
		$user_id = (int)$rs->id;
		if(empty($rs->confirmation)){
			throw new \Exception('ALREADY_CONFIRMED');
		}
		if(!password_verify($token,$rs->confirmation)){
			throw new \Exception('CONFIRMATION_WRONG');
		}

		$sql = "UPDATE `$table` SET `confirmation`='' WHERE `id`=$user_id";
		Config::$db_conn->query($sql);

		return $user_id;
	}

	private static function generate_secure_token() : string {
		return base64_encode(random_bytes(Config::$token_bytes));
	}

	private static function write_autologin_cookie() : void{
		$token = self::generate_secure_token();
		$table = Config::$db_pfix.'token';

		$name = Config::$cookie_pfix.'autologin';
		if(isset($_COOKIE[$name])){
			$old_token = Config::$db_conn->real_escape_string($_COOKIE[$name]);
			$sql = "DELETE FROM `$table` WHERE expires<NOW() OR token='$old_token';";
		} else {
			$sql = "DELETE FROM `$table` WHERE expires<NOW()";
		}
		Config::$db_conn->query($sql);

		$user_id = self::$user_id;
		$token_sql = Config::$db_conn->real_escape_string($token);
		$expire = (int) Config::$autologin_expire;
		$sql = "INSERT INTO `$table` (user_id,token,expires)
			VALUES ($user_id,'$token_sql',DATE_ADD(NOW(),INTERVAL $expire SECOND))";
		Config::$db_conn->query($sql);

		$expire = time()+Config::$autologin_expire;
		if(is_float($expire)) $expire = 0; // if Unix time is overflowing, default to session length;
		setcookie($name, $token, $expire, Config::$cookie_path, '', Config::$cookie_secure);
	}

	private static function delete_autologin_cookie(){
		$name = Config::$cookie_pfix.'autologin';
		if(isset($_COOKIE[$name])){
			$old_token = Config::$db_conn->real_escape_string($_COOKIE[$name]);
			$table = Config::$db_pfix.'token';
			$sql = "DELETE FROM `$table` WHERE expires<NOW() OR token='$old_token';";
			Config::$db_conn->query($sql);
			setcookie($name, '', 1, Config::$cookie_path);
		}
	}

	private function update_autologin_cookie(){
		$name = Config::$cookie_pfix.'autologin';
		if(!isset($_COOKIE[$name])) return;
		$expire = time()+Config::$autologin_expire;
		setcookie($name, $_COOKIE[$name], $expire, Config::$cookie_path, '', Config::$cookie_secure);
	}

	public static function add_access($permission,$save_session = true) : void {
		if(($key = array_search($permission,self::$access)) === false){
			self::$access[] = $permission;
			if($save_session) self::save_session();
		}
	}

	private static function login_successful(): void
	{
		if (Config::$on_login instanceof \Closure) {
			(Config::$on_login)();
		}
	}
}
