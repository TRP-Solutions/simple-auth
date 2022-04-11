<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
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
	private static $lifetime = null;
	private static $cookie_pfix = 'auth_';
	private static $cookie_path = '';
	private static $autologin_expire = 2592000; // 30 days in seconds
	private static $autologin_secure = true;
	private static $token_bytes = 32;
	private static $charset = 'utf8mb4';
	private static $onlogin = null;

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
		if(isset($options['autologin_expire'])) self::$autologin_expire = $options['autologin_expire'];
		if(isset($options['autologin_secure'])) self::$autologin_secure = $options['autologin_secure'];
		if(isset($options['token_bytes'])) self::$token_bytes = $options['token_bytes'];
		if(isset($options['charset'])) self::$charset = $options['charset'];
		if(isset($options['onlogin'])) self::$onlogin = $options['onlogin'];

		if(self::$lifetime){
			ini_set('session.gc_maxlifetime', self::$lifetime);
		}

		session_set_cookie_params(self::$lifetime,self::$cookie_path);
		session_start();
		self::loadsession();
	}

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

	public static function login($username,$password,$autologin = false){
		if(!$username){
			throw new \Exception('USERNAME_NOTSET');
		}
		if(!$password){
			throw new \Exception('PASSWORD_NOTSET');
		}
		self::open_db();

		$username = trim(self::$db_conn->real_escape_string($username));
		$table = self::$db_pfix.'user';
		$sql = "SELECT `id`,`password` FROM `$table` WHERE `username`='$username'";
		$query = self::$db_conn->query($sql);
		if($query->num_rows!=1){
			throw new \Exception('USERNAME_UNKNOWN');
		}

		$rs = $query->fetch_object();
		if(empty($rs->password)){
			throw new \Exception('USER_NOT_ACTIVE');
		}
		if(!password_verify($password,$rs->password)){
			throw new \Exception('PASSWORD_WRONG');
		}

		self::$user_id = (int) $rs->id;
		self::update_access();
		self::savesession();
		if($autologin) self::write_autologin_cookie();
		self::login_successful();
	}

	public static function add_access($permission,$savesession = true){
		if(($key = array_search($permission,self::$access)) === false){
			self::$access[] = $permission;
			if($savesession) self::savesession();
		}
	}

	public static function remove_access($permission,$savesession = true){
		if(($key = array_search($permission,self::$access)) !== false){
			unset(self::$access[$key]);
			if($savesession) self::savesession();
		}
	}

	public static function logout(){
		unset($_SESSION[self::$session_var]);
		self::$user_id = 0;
		self::$access = [];
		self::delete_autologin_cookie();
	}

	public static function create_user($username,$confirmation = false){
		if(!$username){
			throw new \Exception('USERNAME_NOTSET');
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

		return (object) ['user_id'=>self::$db_conn->insert_id];
	}

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

	public static function verify_password($password,$password_confirm = false){
		if(!$password){
			throw new \Exception('PASSWORD_NOTSET');
		}
		if($password_confirm!==false && $password!=$password_confirm){
			throw new \Exception('PASSWORD_NOMATCH');
		}
	}

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

	public static function get_access($user_id = null){
		$user_id = ($user_id===null) ? self::$user_id : (int) $user_id;
		if(empty($user_id)){
			throw new \Exception('INVALID_USERID');
		}

		self::open_db();
		$table = self::$db_pfix.'access';
		$sql = "SELECT GROUP_CONCAT(`permission`) as permission FROM `$table` WHERE `user_id`='$user_id'";
		$permission = explode(',',self::$db_conn->query($sql)->fetch_object()->permission);

		return $permission;
	}

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

	private static function savepassword($user_id,$password){
		self::open_db();
		$table = self::$db_pfix.'user';
		$password = empty($password) ? '' : password_hash($password, PASSWORD_DEFAULT);
		$sql = "UPDATE `$table` SET `password`='$password' WHERE `id`='$user_id'";
		self::$db_conn->query($sql);
	}

	private static function generate_secure_token(){
		return base64_encode(random_bytes(self::$token_bytes));
	}

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

		$expire = (int) self::$autologin_expire;
		$user_id = self::$user_id;
		$sql = "INSERT INTO `$table` (user_id,token,expires)
			VALUES ($user_id,'$token',DATE_ADD(NOW(),INTERVAL $expire SECOND))";
		self::$db_conn->query($sql);

		$expire = time()+self::$autologin_expire;
		if(is_float($expire)) $expire = 0; // if Unix time is overflowing, default to session length;
		setcookie($name, $token, $expire, self::$cookie_path, '', self::$autologin_secure); // require HTTPS
	}

	private function update_autologin_cookie(){
		$name = self::$cookie_pfix.'autologin';
		if(!isset($_COOKIE[$name])) return;
		$expire = time()+self::$autologin_expire;
		setcookie($name, $_COOKIE[$name], $expire, self::$cookie_path, '', self::$autologin_secure);
	}

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

	private static function savesession(){
		$json = json_encode([
			'user_id' => self::$user_id,
			'access' => self::$access
		]);

		$_SESSION[self::$session_var] = $json;
	}

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

	private static function open_db(){
		if(!self::$db_conn){
			self::$db_conn = new mysqli(self::$db_host,self::$db_user,self::$db_pass,self::$db_base);
			if(self::$db_conn->connect_error){
				throw new \Exception('CONNECTION_ERROR');
			}
			self::$db_conn->set_charset(self::$charset);
		}
	}

	private static function login_successful(){
		if(isset(self::$onlogin) && is_callable(self::$onlogin)){
			$callable = self::$onlogin;
			$callable();
		}
	}

	public static function user_id(){
		return self::$user_id;
	}

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
		else
			return $code;
	}
}
