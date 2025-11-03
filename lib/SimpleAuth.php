<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

$autoload = '../vendor/autoload.php';
if (file_exists($autoload)) {
	require $autoload;
}

use RobThree\Auth\Algorithm;
use RobThree\Auth\Providers\Qr\EndroidQrCodeProvider;
use RobThree\Auth\TwoFactorAuth;


class SimpleAuth {
	private static $user_id = 0;
	private static $access = [];
	private static $db_conn = null;

	// configurable variables
	private static $db_host = 'localhost';
	private static $db_user = '';
	private static $db_pass = '';
	private static $db_base = '';
	private static $db_pfix = 'auth_';
	private static $session_var = 'auth';
	private static $lifetime = 0;
	private static $cookie_pfix = 'auth_';
	private static $cookie_path = '';
	private static $cookie_secure = true;
	private static $autologin_expire = 2592000; // 30 days in seconds
	private static $token_bytes = 32;
	private static $charset = 'utf8mb4';
	private static $onlogin = null;

	private static $tfa;

	public static function tfa_supported(){
		return class_exists('\RobThree\Auth\TwoFactorAuth')
			&& class_exists('\Endroid\QrCode\QrCode');
	}

	/**
	 *
	 * Configures SimpleAuth with custom options if default values aren't suited.
	 *
	 * @param string[] $options Custom options.
	 * @return void
	 * @throws Exception
	 */
	public static function configure($options = []){
		if(isset($options['db_host'])) self::$db_host = $options['db_host'];
		if(isset($options['db_user'])) self::$db_user = $options['db_user'];
		if(isset($options['db_pass'])) self::$db_pass = $options['db_pass'];
		if(isset($options['db_base'])) self::$db_base = $options['db_base'];
		if(isset($options['db_pfix'])) self::$db_pfix = $options['db_pfix'];
		if(isset($options['session_var'])) self::$session_var = $options['session_var'];
		if(isset($options['lifetime'])) self::$lifetime = $options['lifetime'];
		if(isset($options['cookie_pfix'])) self::$cookie_pfix = $options['cookie_pfix'];
		if(isset($options['cookie_path'])) self::$cookie_path = $options['cookie_path'];
		if(isset($options['cookie_secure'])) self::$cookie_secure = $options['cookie_secure'];
		if(isset($options['autologin_expire'])) self::$autologin_expire = $options['autologin_expire'];
		if(isset($options['token_bytes'])) self::$token_bytes = $options['token_bytes'];
		if(isset($options['charset'])) self::$charset = $options['charset'];
		if(isset($options['onlogin'])) self::$onlogin = $options['onlogin'];

		if(self::$lifetime){
			ini_set('session.gc_maxlifetime', self::$lifetime);
		}

		session_set_cookie_params(self::$lifetime, self::$cookie_path, null, self::$cookie_secure);
		session_start();
		if(self::$lifetime) {
			setcookie(session_name(), session_id(), time()+self::$lifetime, self::$cookie_path, null, self::$cookie_secure);
		}
		self::loadsession();
	}

	/**
	 *
	 * Checks if the current user has one or more specified permissions.
	 *
	 * @param string|array ...$permission_list One or more permissions or arrays of permissions to check.
	 * @return bool True if the user has at least one of the specified permission, otherwise false.
	 */
	public static function access(...$permission_list){
		if(!self::$access) return false;

		foreach($permission_list as $permission){
			if(is_string($permission) && in_array($permission,self::$access)) return true;
			if(is_array($permission)){
				$valid = true;
				foreach($permission as $string){
					if(!in_array($string,self::$access)) $valid = false;
				}
				if($valid) return true;
			}
		}
		return false;
	}

	/**
	 *
	 * Authenticates a user by verifying the user's username and password,
	 * it also creates a persistent remember me cookie.
	 *
	 * @param string $username The username provided by the user.
	 * @param string $password The password provided by the user.
	 * @param string $totp [OPTIONAL] 2fa code send by user.
	 * @param bool $autologin [OPTIONAL] Whether to enable the remember me cookie feature. (default: false)
	 * @return bool if this is false the user has 2fa enabled
	 * @throws \Random\RandomException
	 */
	public static function login($username, $password, $autologin = false) {
		if (!$username) { throw new \Exception('USERNAME_NOTSET'); }
		if (!$password) { throw new \Exception('PASSWORD_NOTSET'); }

		self::open_db();

		$username = trim(self::$db_conn->real_escape_string($username));
		$table = self::$db_pfix . 'user';

		$sql = "SELECT `id`,`password`,`tfa` FROM `$table` WHERE `username`='$username'";
		$query = self::$db_conn->query($sql);
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
		if (!empty($rs->tfa)) {
			if(!self::tfa_supported()){
				throw new \Exception('TFA_NOT_SUPPORTED');
			}
			$user_id  = (int)$rs->id;
			$table = self::$db_pfix . 'pending';
			$sql = "INSERT INTO `$table` (user_id, username, expires)
			VALUES ($user_id, '$username', DATE_ADD(NOW(), INTERVAL 5 MINUTE))
			ON DUPLICATE KEY UPDATE
				username = VALUES(username),
				expires = VALUES(expires)";

			self::$db_conn->query($sql);
			return false;
		}

		self::$user_id = (int)$rs->id;
		self::update_access();
		self::savesession();
		if ($autologin) self::write_autologin_cookie();
		self::login_successful();
		return true;
	}

	/**
	 *
	 * Authenticates a user often used for 2fa authentication,
	 * needs an active and valid 2fa pending request
	 *
	 * @param string $username The username provided by the user.
	 * @return bool
	 * @throws \Random\RandomException
	 */
	public static function login_with_tfa_code($username, $tfa_code){
		self::open_db();
		$username = trim(self::$db_conn->real_escape_string($username));
		if(!self::tfa_supported()){
			throw new \Exception('TFA_NOT_SUPPORTED');
		}

		$table = self::$db_pfix . 'user';
		$sql = "SELECT `id` FROM `$table` WHERE `username`='$username'";
		$query = self::$db_conn->query($sql);
		$rs = $query->fetch_object();
		$userId = $rs->id;

		$table = self::$db_pfix . 'pending';
		$sql = "SELECT `expires` < NOW() as `expired` FROM `$table` WHERE `user_id`='$userId'";
		$query = self::$db_conn->query($sql);
		if ($query->num_rows !== 1 || $query->fetch_object()->expired) {
			throw new \Exception('TFA_NOT_REQUESTED');
		}

		if(!self::validate_tfa_code($userId, $tfa_code)) {
			throw new \Exception('TFA_INVALID');
		}

		$sql = "DELETE FROM `$table` WHERE `user_id`='$userId'";
		self::$db_conn->query($sql);

		self::$user_id = $userId;
		self::update_access();
		self::savesession();
		self::write_autologin_cookie();
		self::login_successful();
		return true;
	}

	/**
	 *
	 * Adds a specific permission to the user's access list.
	 *
	 * @param string $permission The permission to add.
	 * @param bool $savesession [OPTIONAL] Whether to save the updated list to the session. (default: true)
	 * @return void
	 */
	public static function add_access($permission,$savesession = true){
		if(($key = array_search($permission,self::$access)) === false){
			self::$access[] = $permission;
			if($savesession) self::savesession();
		}
	}

	/**
	 *
	 * Removes a specific permission from the user's access list.
	 *
	 * @param string $permission The permission to remove.
	 * @param bool $savesession [OPTIONAL] Whether to save the updated list to the session. (default: true)
	 * @return void
	 */
	public static function remove_access($permission,$savesession = true){
		if(($key = array_search($permission,self::$access)) !== false){
			unset(self::$access[$key]);
			if($savesession) self::savesession();
		}
	}

	/**
	 *
	 * Log out user and delete autologin cookies and forget session
	 *
	 * @return void
	 * @throws Exception
	 */
	public static function logout(){
		unset($_SESSION[self::$session_var]);
		self::$user_id = 0;
		self::$access = [];
		self::delete_autologin_cookie();
	}


	/**
	 *
	 * Creates a username if the inputted username is not already in use.
	 *
	 * @param string $username New username.
	 * @param boolean $includeTfa Should the user have 2fa enabled.
	 * @return object The user string. (property: user_id, qr)
	 * @throws Exception
	 */
	public static function create_user($username, $includeTfa){
		if(!$username){
			throw new \Exception('USERNAME_NOTSET');
		}

		if($includeTfa && !self::tfa_supported()){
			throw new \Exception('TFA_NOT_SUPPORTED');
		}
		self::open_db();

		$username = trim(self::$db_conn->real_escape_string($username));
		$table = self::$db_pfix.'user';
		$sql = "SELECT `id` FROM `$table` WHERE `username`='$username'";
		$query = self::$db_conn->query($sql);
		if($query->num_rows==1){
			throw new \Exception('USERNAME_INUSE');
		}

		$sql = "INSERT INTO `$table` (`username`) VALUES ('$username')";
		self::$db_conn->query($sql);
		$userId = self::$db_conn->insert_id;

		$qr = null;
		if($includeTfa){
			$tfaInfo = self::create_tfa_code((string)$userId, $username);
			$qr = $tfaInfo->qr;
		}

		return (object) [
			'user_id'=>$userId,
			'qr' => $qr
		];
	}

	/**
	 *
	 * Generates and stores a new confirmation token for a user.
	 *
	 * @param int $user_id User's id.
	 * @return object The confirmation string. (property: confirmation)
	 * @throws Exception
	 */
	public static function confirm_hash($user_id){
		if(!$user_id){
			throw new \Exception('INVALID_USERID');
		}
		self::open_db();

		$table = self::$db_pfix.'user';
		$sql = "SELECT `username` FROM `$table` WHERE `id`='$user_id'";
		$query = self::$db_conn->query($sql);
		if($query->num_rows!=1){
			throw new \Exception('INVALID_USERID');
		}
		$rs = $query->fetch_object();

		$token = self::generate_secure_token();
		$token_sql = password_hash($token, PASSWORD_DEFAULT);
		$confirmation = base64_encode($rs->username.':'.$token);

		$sql = "UPDATE `$table` SET `confirmation`='$token_sql' WHERE `id`='$user_id'";
		self::$db_conn->query($sql);

		return (object) ['confirmation'=>$confirmation];
	}

	/**
	 *
	 * Verifies a user's account confirmation token.
	 *
	 * @param string $confirmation Base64 encoded confirmation string.
	 * @return object The verified user's UserId and username.
	 * @throws Exception
	 */
	public static function confirm_verify($confirmation){
		if(!$confirmation){
			throw new \Exception('CONFIRMATION_NOTSET');
		}

		$str = base64_decode($confirmation);
		if($str===false){
			throw new \Exception('CONFIRMATION_INVALID');
		}
		$array = explode(':',$str);
		if(sizeof($array)!==2){
			throw new \Exception('CONFIRMATION_INVALID');
		}
		list($username,$token) = $array;

		self::open_db();
		$sql_username = trim(self::$db_conn->real_escape_string($username));
		$table = self::$db_pfix.'user';
		$sql = "SELECT `id`,`confirmation` FROM `$table` WHERE `username`='$sql_username'";
		$query = self::$db_conn->query($sql);
		if($query->num_rows!=1){
			throw new \Exception('USERNAME_UNKNOWN');
		}

		$rs = $query->fetch_object();
		if(empty($rs->confirmation)){
			throw new \Exception('ALREADY_CONFIRMED');
		}
		if(!password_verify($token,$rs->confirmation)){
			throw new \Exception('CONFIRMATION_WRONG');
		}

		$sql = "UPDATE `$table` SET `confirmation`='' WHERE `id`=$rs->id";
		self::$db_conn->query($sql);

		return (object) ['user_id'=>$rs->id,'username'=>$username];
	}

	/**
	 *
	 * Change user's password.
	 *
	 * @param string $password New unhashed password.
	 * @param int $user_id [OPTIONAL] User's id. (default: current user)
	 * @param string $password_current The current unhashed password.
	 * @return void
	 * @throws Exception
	 */
	public static function change_password($password,$user_id = null,$password_current = false){
		if(!self::$user_id && $user_id===null){
			throw new \Exception('USER_NOT_LOGGED_IN');
		}
		$user_id = ($user_id===null) ? self::$user_id : (int) $user_id;
		if(empty($user_id)){
			throw new \Exception('INVALID_USERID');
		}
		if($password_current!==false){
			self::open_db();
			$table = self::$db_pfix.'user';
			$sql = "SELECT `password` FROM `$table` WHERE id='$user_id'";
			$query = self::$db_conn->query($sql);
			$rs = $query->fetch_object();
			if(!password_verify($password_current,$rs->password)){
				throw new \Exception('PASSWORD_WRONG');
			}
		}

		self::savepassword($user_id,$password);
	}

	/**
	 *
	 * Matches two password.
	 *
	 * @param string $password Password that needs to be matched.
	 * @param string $password_confirm [OPTIONAL] The correct password. (default: false)
	 * @return void
	 * @throws Exception
	 */
	public static function verify_password($password,$password_confirm = false){
		if(!$password){
			throw new \Exception('PASSWORD_NOTSET');
		}
		if($password_confirm!==false && $password!=$password_confirm){
			throw new \Exception('PASSWORD_NOMATCH');
		}
	}

	/**
	 *
	 * Change user's username.
	 *
	 * @param string $username New username.
	 * @param int $user_id [OPTIONAL] User's id. (default: current user)
	 * @return void
	 * @throws Exception
	 */
	public static function change_username($username,$user_id = null){
		if(!$username){
			throw new \Exception('USERNAME_NOTSET');
		}
		if(!self::$user_id && $user_id===null){
			throw new \Exception('USER_NOT_LOGGED_IN');
		}
		self::open_db();
		$username = trim(self::$db_conn->real_escape_string($username));
		$table = self::$db_pfix.'user';
		$user_id = ($user_id===null) ? self::$user_id : (int) $user_id;
		if(empty($user_id)){
			throw new \Exception('INVALID_USERID');
		}
		$sql = "SELECT `id`,`password` FROM `$table` WHERE `username`='$username' AND `id`!='$user_id'";
		$query = self::$db_conn->query($sql);
		if($query->num_rows==1){
			throw new \Exception('USERNAME_INUSE');
		}

		$sql = "UPDATE `$table` SET `username`='$username' WHERE `id`='$user_id'";
		self::$db_conn->query($sql);
	}

	/**
	 *
	 * Updates the user's access permission in the database.
	 *
	 * @param array $access_list The user's permission to assign in the database.
	 * @param int $user_id [OPTIONAL] The id of the user whose permission should be changed. (default: current user)
	 * @return void
	 * @throws Exception
	 */
	public static function change_access($access_list,$user_id = null){
		if(!self::$user_id && $user_id===null){
			throw new \Exception('USER_NOT_LOGGED_IN');
		}
		self::open_db();
		$table = self::$db_pfix.'access';
		$user_id = ($user_id===null) ? self::$user_id : (int) $user_id;
		if(empty($user_id)){
			throw new \Exception('INVALID_USERID');
		}

		$sql = "DELETE FROM `$table` WHERE `user_id`='$user_id'";
		self::$db_conn->query($sql);
		if(is_array($access_list)){
			foreach($access_list as $access){
				$permission = self::$db_conn->real_escape_string($access);
				$sql = "INSERT INTO `$table` (`user_id`,`permission`) VALUES ('$user_id','$permission')";
				self::$db_conn->query($sql);
			}
		}
	}

	/**
	 *
	 * Refreshes the current user's access permissions from the database.
	 *
	 * @return void
	 */
	private static function update_access(){
		if(isset(self::$user_id)){
			$table = self::$db_pfix.'access';
			$user_id = self::$user_id;
			$sql = "SELECT `permission` FROM `$table` WHERE `user_id`='$user_id'";
			$query = self::$db_conn->query($sql);
			while($rs = $query->fetch_object()){
				self::add_access($rs->permission,false);
			}
		}
	}

	/**
	 *
	 * Gets a user's permission.
	 *
	 * @param int $user_id [OPTIONAL] User's id. (default: current user).
	 * @return array|false|string[]
	 * @throws Exception
	 */
	public static function get_access($user_id = null){
		$user_id = ($user_id===null) ? self::$user_id : (int) $user_id;
		if(empty($user_id)){
			throw new \Exception('INVALID_USERID');
		}

		self::open_db();
		$table = self::$db_pfix.'access';
		$sql = "SELECT GROUP_CONCAT(`permission`) as permission FROM `$table` WHERE `user_id`='$user_id'";
		$permission = self::$db_conn->query($sql)->fetch_object()->permission;
		return $permission ? explode(',',$permission) : [];
	}

	/**
	 *
	 * Gets a user's id from their username.
	 *
	 * @param string $username User's username.
	 * @return int User's id.
	 * @throws Exception
	 */
	public static function get_user_id($username){
		if(!$username){
			throw new \Exception('USERNAME_NOTSET');
		}

		self::open_db();
		$username = trim(self::$db_conn->real_escape_string($username));
		$table = self::$db_pfix.'user';
		$sql = "SELECT `id` FROM `$table` WHERE `username`='$username'";
		$query = self::$db_conn->query($sql);
		if($query->num_rows!=1){
			throw new \Exception('USERNAME_UNKNOWN');
		}

		$rs = $query->fetch_object();
		return (int) $rs->id;
	}

	/**
	 *
	 * Disables a user'.'s account by deleting user's access and tokens and
	 * setting their password to nothing so the user cant login.
	 *
	 * @param int $user_id The user's id.
	 * @return void
	 * @throws Exception
	 */
	public static function disable($user_id){
		if(empty($user_id)){
			throw new \Exception('INVALID_USERID');
		}

		self::open_db();
		$table = self::$db_pfix.'access';
		$sql = "DELETE FROM `$table` WHERE `user_id`='$user_id'";
		self::$db_conn->query($sql);

		$table = self::$db_pfix.'token';
		$sql = "DELETE FROM `$table` WHERE `user_id`='$user_id'";
		self::$db_conn->query($sql);

		$table = self::$db_pfix.'user';
		$sql = "UPDATE `$table` SET `password`='',`confirmation`='' WHERE `id`='$user_id'";
		self::$db_conn->query($sql);
	}

	/**
	 *
	 * Takes unhashed password and saves a hashed version in the database.
	 *
	 * @param int $user_id User's id.
	 * @param string $password Unhashed password.
	 * @return void
	 * @throws Exception
	 */
	private static function savepassword($user_id,$password){
		self::open_db();
		$table = self::$db_pfix.'user';
		$password = empty($password) ? '' : password_hash($password, PASSWORD_DEFAULT);
		$sql = "UPDATE `$table` SET `password`='$password' WHERE `id`='$user_id'";
		self::$db_conn->query($sql);
	}

	/**
	 *
	 * Generates a random token with length of $token_bytes.
	 *
	 * @return string
	 * @throws \Random\RandomException
	 */
	private static function generate_secure_token(){
		return base64_encode(random_bytes(self::$token_bytes));
	}

	/**
	 *
	 * Creates or refreshes the user's autologin cookie and database token.
	 *
	 * @return void
	 * @throws \Random\RandomException
	 */
	private static function write_autologin_cookie(){
		$token = self::generate_secure_token();
		$table = self::$db_pfix.'token';

		$name = self::$cookie_pfix.'autologin';
		if(isset($_COOKIE[$name])){
			$old_token = self::$db_conn->real_escape_string($_COOKIE[$name]);
			$sql = "DELETE FROM `$table` WHERE expires<NOW() OR token='$old_token';";
		} else {
			$sql = "DELETE FROM `$table` WHERE expires<NOW()";
		}
		self::$db_conn->query($sql);

		$user_id = self::$user_id;
		$token_sql = self::$db_conn->real_escape_string($token);
		$expire = (int) self::$autologin_expire;
		$sql = "INSERT INTO `$table` (user_id,token,expires)
			VALUES ($user_id,'$token_sql',DATE_ADD(NOW(),INTERVAL $expire SECOND))";
		self::$db_conn->query($sql);

		$expire = time()+self::$autologin_expire;
		if(is_float($expire)) $expire = 0; // if Unix time is overflowing, default to session length;
		setcookie($name, $token, $expire, self::$cookie_path, '', self::$cookie_secure);
	}

	/**
	 *
	 * Extends the lifetime of an existing autologin cookie.
	 *
	 * @return void
	 */
	private function update_autologin_cookie(){
		$name = self::$cookie_pfix.'autologin';
		if(!isset($_COOKIE[$name])) return;
		$expire = time()+self::$autologin_expire;
		setcookie($name, $_COOKIE[$name], $expire, self::$cookie_path, '', self::$cookie_secure);
	}

	/**
	 *
	 * Deletes autologin tokens that are expired or if it is the old token.
	 *
	 * @return void
	 * @throws Exception
	 */
	private static function delete_autologin_cookie(){
		$name = self::$cookie_pfix.'autologin';
		if(isset($_COOKIE[$name])){
			self::open_db();
			$old_token = self::$db_conn->real_escape_string($_COOKIE[$name]);
			$table = self::$db_pfix.'token';
			$sql = "DELETE FROM `$table` WHERE expires<NOW() OR token='$old_token';";
			self::$db_conn->query($sql);
			setcookie($name, '', 1, self::$cookie_path);
		}
	}

	/**
	 *
	 * Saves the current user's login information to the PHP session.
	 *
	 * @return void
	 */
	private static function savesession(){
		$json = json_encode([
			'user_id' => self::$user_id,
			'access' => self::$access
		]);

		$_SESSION[self::$session_var] = $json;
	}

	/**
	 *
	 * Tries to load session else it will try to load the session from the autologin cookie.
	 * if the cookie is invalid or expired it will delete the cookie and logout the user
	 * and if its valid it will create a new session so the login is restored.
	 *
	 * @return void
	 * @throws Exception
	 */
	static private function loadsession(){
		if(isset($_SESSION[self::$session_var])){
			$json = json_decode($_SESSION[self::$session_var]);
			self::$user_id = $json->user_id;
			self::$access = $json->access;
		} elseif(isset($_COOKIE[self::$cookie_pfix.'autologin'])){
			self::open_db();
			$token = self::$db_conn->real_escape_string($_COOKIE[self::$cookie_pfix.'autologin']);
			$table = self::$db_pfix.'token';
			$sql = "SELECT user_id,token,expires<=NOW() as expired FROM `$table` WHERE token='$token'";
			$query = self::$db_conn->query($sql);
			if($query->num_rows!=1){
				self::delete_autologin_cookie();
				return;
			}
			$rs = $query->fetch_object();
			if($rs->expired){
				self::delete_autologin_cookie();
				$sql = "DELETE FROM `$table` WHERE expires<NOW()";
				self::$db_conn->query($sql);
				return;
			}
			self::$user_id = (int) $rs->user_id;
			self::write_autologin_cookie();
				self::update_access();
			self::savesession();
			self::login_successful();
		}
	}

	/**
	 *
	 * Handles HTTP Basic Authentication for the current request.
	 *
	 * @param string $realm [OPTIONAL] The authentication realm displayed in the browser's login prompt. (default: "SimpleAuth Login").
	 * @return void
	 */
	public static function www_authenticate($realm = 'SimpleAuth Login'){
		if(self::$user_id) {
			return;
		}
		if(empty($_SERVER['PHP_AUTH_USER']) || empty($_SERVER['PHP_AUTH_PW'])) {
			self::www_dialog($realm);
		}
		else {
			try {
				self::login($_SERVER['PHP_AUTH_USER'],$_SERVER['PHP_AUTH_PW']);
			}
			catch(\Exception $e){
				self::www_dialog($realm,SimpleAuth::error_string($e->getMessage()));
			}
		}
	}

	/**
	 *
	 * Sends an HTTP Basic Authentication challenge and terminates execution.
	 *
	 * @param string $realm The authentication realm displayed in the browser's login dialog.
	 * @param string $message [OPTIONAL] message to include in the HTTP response. (default: "Unauthorized").
	 * @return void
	 */
	private static function www_dialog($realm, $message = 'Unauthorized') {
		header('WWW-Authenticate: Basic realm="'.$realm.'", charset="UTF-8"');
		header('HTTP/1.1 401 '.$message);
		echo $message;
		exit;
	}

	/**
	 *
	 * Creates a database connection in no current connection exists.
	 *
	 * @return void
	 * @throws Exception If the database connection fails.
	 */
	private static function open_db(){
		if(!self::$db_conn){
			self::$db_conn = new mysqli(self::$db_host,self::$db_user,self::$db_pass,self::$db_base);
			if(self::$db_conn->connect_error){
				throw new \Exception('CONNECTION_ERROR');
			}
			self::$db_conn->set_charset(self::$charset);
		}
	}

	/**
	 *
	 * Calls the $onLogin event if it is set.
	 *
	 * @return void
	 */
	private static function login_successful(){
		if(isset(self::$onlogin) && is_callable(self::$onlogin)){
			$callable = self::$onlogin;
			$callable();
		}
	}

	/**
	 *
	 * Gets the current user's id.
	 *
	 * @return int User's id.
	 */
	public static function user_id(){
		return self::$user_id;
	}

	/**
	 *
	 * Gets the current user's username.
	 *
	 * @return string User's username.
	 */
	public static function username(){
		$user_id = self::$user_id;

		self::open_db();
		$table = self::$db_pfix.'user';
		$sql = "SELECT `username` FROM `$table` WHERE id='$user_id'";
		$query = self::$db_conn->query($sql);
		$rs = $query->fetch_object();
		return $rs->username;
	}

	/**
	 *
	 * Get the error message based on the provided error code.
	 *
	 * @param string $code Error code.
	 * @return string Error message.
	 */
	public static function error_string($code){
		if($code=='USERNAME_NOTSET')
			return "Username not set";
		else if($code=='USERNAME_UNKNOWN')
			return "Username unknown";
		else if($code=='USERNAME_INUSE')
			return "Username already taken";
		else if($code=='USER_NOT_LOGGED_IN')
			return "User is not logged in";
		else if($code=='USER_NOT_ACTIVE')
			return "User is not active";
		else if($code=='PASSWORD_NOTSET')
			return "Password not set";
		else if($code=='PASSWORD_WRONG')
			return "Wrong password";
		else if($code=='PASSWORD_NOMATCH')
			return "Password does not match the confirm password";
		else if($code=='INVALID_USERID')
			return "Invalid user id";
		else if($code=='CONFIRMATION_NOTSET')
			return "Confirmation not set";
		else if($code=='CONFIRMATION_INVALID')
			return "Confirmation is invalid";
		else if($code=='ALREADY_CONFIRMED')
			return "User is already confirmed";
		else if($code=='CONFIRMATION_WRONG')
			return "Wrong confirmation";
		else if($code=='CONNECTION_ERROR')
			return "Connection Error";
		else if($code=='TFA_INVALID')
			return "Two factor code is invalid";
		else if ($code=='TFA_NOT_SUPPORTED')
			return "Two factor code is not supported";
		else if($code=='TFA_NOT_REQUESTED')
			return "Two factor code is not requested";
		else
			return $code;
	}

	/**
	 *
	 * Get 2fa instance.
	 *
	 * @return TwoFactorAuth
	 * @throws \RobThree\Auth\TwoFactorAuthException
	 */
	private static function getTfa()
	{
		if (!self::$tfa) {
			$qr  = new EndroidQrCodeProvider();
			$tfa = new TwoFactorAuth($qr, 'SimpleAuth', 6, 30, Algorithm::Sha1);
			self::$tfa = $tfa;
		}
		return self::$tfa;
	}


	/**
	 *
	 * Create 2fa code for user.
	 *
	 * @param string $user_id User's userId.
	 * @return object (property: qr, hasSecret)
	 * @throws \RobThree\Auth\TwoFactorAuthException
	 */
	public static function create_tfa_code(string $user_id, $username = null)
	{
		if(!self::tfa_supported()){
			throw new \Exception('TFA_NOT_SUPPORTED');
		}

		$tfa = self::getTfa();

		$secret = self::load_user_tfa_secret($user_id);

		if (!$secret) {
			$secret = $tfa->createSecret(160);
			$table = self::$db_pfix.'user';

			self::open_db();
			$sql = "UPDATE `$table` SET `tfa` = '$secret' WHERE `id` = '$user_id'";
			self::$db_conn->query($sql);
		}

		if(!$username) $username = self::username();
		// Display as SimpleAuth:Username
		$label = "SimpleAuth:" . $username;
		$qrImgDataUri = $tfa->getQRCodeImageAsDataUri($label, $secret);

		return (object) [
			'qr'		=> $qrImgDataUri,
			'hasSecret' => true
		];
	}

	/**
	 *
	 * Deletes 2fa code for user.
	 *
	 * @param string $user_id User's user_id.
	 */
	public static function delete_tfa_code(string $user_id)
	{
		self::open_db();
		$table = self::$db_pfix.'user';
		$sql = "UPDATE `$table` SET tfa = NULL WHERE `id`='$user_id'";
		self::$db_conn->query($sql);
	}

	/**
	 *
	 * Validate a user inputted 2fa code.
	 *
	 * @param string $username User's username.
	 * @param string $code User provided code.
	 * @return bool
	 * @throws \RobThree\Auth\TwoFactorAuthException
	 */
	public static function validate_tfa_code(string $user_id, string $code)
	{
		if(!self::tfa_supported()){
			throw new \Exception('TFA_NOT_SUPPORTED');
		}

		$tfa = self::getTfa();
		if (!$tfa) {
			return false;
		}

		$secret = self::load_user_tfa_secret($user_id);
		if (!$secret) {
			return false;
		}

		return $tfa->verifyCode($secret, $code, 2);
	}

	/**
	*
	* Get user's 2fa secret from database.
	*
	 * @param string $user_id User's userId.
	 * @return string|null
	 * @throws Exception
	 */
	private static function load_user_tfa_secret(string $user_id)
	{
		self::open_db();
		$table = self::$db_pfix.'user';
		$sql = "SELECT `tfa` FROM `$table` WHERE `id` = '$user_id'";
		$query = self::$db_conn->query($sql);
		$rs = $query->fetch_object();
		if($rs->tfa === "") return null;
		return $rs->tfa;
	}

	/**
	 *
	 * Checks if the current user has 2fa enabled
	 *
	 * @return bool if the user has 2fa enabled.
	 */
	public static function has_tfa()
	{
		self::open_db();

		$table = self::$db_pfix . 'user';

		$user_id = self::$user_id;
		$sql = "SELECT `username`, `tfa` FROM `$table` WHERE `id` = '$user_id'";
		$query = self::$db_conn->query($sql);
		if ($query->num_rows !== 1) {
			throw new \Exception('USERNAME_UNKNOWN');
		}
		$rs = $query->fetch_object();
		return $rs->tfa != null;
	}
}