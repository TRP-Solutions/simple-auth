<?php
class SimpleAuth {
	private $user_id = 0;
	private $access = [];
	private $db_conn = null;
	
	// configurable variables
	private $db_host = 'localhost';
	private $db_user = '';
	private $db_pass = '';
	private $db_base = '';
	private $db_pfix = 'auth_';
	private $session_var = 'auth';
	private $lifetime = null;
	private $cookie_pfix = 'auth_';
	private $autologin_expire = 2592000; // 30 days in seconds
	private $autologin_bytes = 32;
	private $autologin_secure = true;
	
	function __construct($options = []){
		if(isset($options['db_host'])) $this->db_host = $options['db_host'];
		if(isset($options['db_user'])) $this->db_user = $options['db_user'];
		if(isset($options['db_pass'])) $this->db_pass = $options['db_pass'];
		if(isset($options['db_base'])) $this->db_base = $options['db_base'];
		if(isset($options['db_pfix'])) $this->db_pfix = $options['db_pfix'];
		if(isset($options['session_var'])) $this->session_var = $options['session_var'];
		if(isset($options['lifetime'])) $this->lifetime = $options['lifetime'];
		if(isset($options['cookie_pfix'])) $this->cookie_pfix = $options['cookie_pfix'];
		if(isset($options['autologin_expire'])) $this->autologin_expire = $options['autologin_expire'];
		if(isset($options['autologin_bytes'])) $this->autologin_bytes = $options['autologin_bytes'];
		if(isset($options['autologin_secure'])) $this->autologin_secure = $options['autologin_secure'];
		
		if($this->lifetime) {
			ini_set('session.gc_maxlifetime', $this->lifetime);
			session_set_cookie_params($this->lifetime);
		}
		
		session_start();
		$this->loadsession();
	}
	
	public function access(...$permission_list){
		if(!$this->access) return false;
		
		foreach($permission_list as $permission){
			if(is_string($permission) && in_array($permission,$this->access)) return true;
			if(is_array($permission)){
				$valid = true;
				foreach($permission as $string){
					if(!in_array($string,$this->access)) $valid = false;
				}
				if($valid) return true;
			} 
		}
		return false;
	}
	
	public function login($username,$password,$autologin = false){
		if(!$username){
			return (object) ['error'=>'USERNAME_NOTSET'];
		}
		if(!$password){
			return (object) ['error'=>'PASSWORD_NOTSET'];
		}
		$this->open_db();
		
		$username = $this->db_conn->real_escape_string($username);
		$table = $this->db_pfix.'user';
		$sql = "SELECT id,password FROM $table WHERE username='$username'";
		$query = $this->db_conn->query($sql);
		if($query->num_rows!=1){
			return (object) ['error'=>'USERNAME_UNKNOWN'];
		}
		
		$rs = $query->fetch_object();
		if(!password_verify($password,$rs->password)){
			return (object) ['error'=>'PASSWORD_WRONG'];
		}
		
		$this->user_id = $rs->id;
		$this->update_access();
		$this->savesession();
		if($autologin) $this->write_autologin_cookie();
		
		return (object) ['success'=>true];
	}
	
	public function add_access($permission,$savesession = true){
		$this->access[] = $permission;
		if($savesession) $this->savesession();
	}
	
	public function logout(){
		unset($_SESSION[$this->session_var]);
		$this->user_id = 0;
		$this->access = [];
		$this->delete_autologin_cookie();
	}
	
	public function create_user($username,$password,$password_confirm){
		if(!$username){
			return (object) ['error'=>'USERNAME_NOTSET'];
		}
		if(!$password){
			return (object) ['error'=>'PASSWORD_NOTSET'];
		}
		$this->open_db();
		
		$username = $this->db_conn->real_escape_string($username);
		$table = $this->db_pfix.'user';
		$sql = "SELECT id,password FROM $table WHERE username='$username'";
		$query = $this->db_conn->query($sql);
		if($query->num_rows==1){
			return (object) ['error'=>'USERNAME_INUSE'];
		}
		if($password!=$password_confirm){
			return (object) ['error'=>'PASSWORD_NOMATCH'];
		}
		$password = password_hash($password, PASSWORD_DEFAULT);
		$sql = "INSERT INTO $table (username,password) VALUES ('$username','$password')";
		$this->db_conn->query($sql);
		
		return (object) ['success'=>true,'user_id'=>$this->db_conn->insert_id];
	}
	
	public function change_password($password){
		if(!$password){
			return (object) ['error'=>'PASSWORD_NOTSET'];
		}
		if(!$this->user_id){
			return (object) ['error'=>'USER_NOT_LOGGED_IN'];
		}
		$this->open_db();
		$password = password_hash($password, PASSWORD_DEFAULT);
		$table = $this->db_pfix.'user';
		$sql = "UPDATE $table SET password='$password' WHERE id=$this->user_id";
		$this->db_conn->query($sql);
		return (object) ['success'=>true];
	}

	private function update_access(){
		if(isset($this->user_id)){
			$table = $this->db_pfix.'access';
			$sql = "SELECT permission FROM $table WHERE user_id='$this->user_id'";
			$query = $this->db_conn->query($sql);
			while($rs = $query->fetch_object()){
				$this->add_access($rs->permission,false);
			}
		}
	}

	private function generate_secure_token(){
		return base64_encode(random_bytes($this->autologin_bytes));
	}

	private function write_autologin_cookie(){
		$token = $this->generate_secure_token();
		$table = $this->db_pfix.'token';

		$sql = "DELETE FROM $table WHERE expires<NOW()";
		$this->db_conn->query($sql);
		$sql = "INSERT INTO $table (user_id,token,expires)
			VALUES ($this->user_id,'$token',DATE_ADD(NOW(),INTERVAL $this->autologin_expire SECOND))";
		$this->db_conn->query($sql);

		$expire = time()+$this->autologin_expire;
		if(is_float($expire)) $expire = 0; // if Unix time is overflowing, default to session length;
		setcookie($this->cookie_pfix.'autologin', $token, $expire, '', '', $this->autologin_secure); // require HTTPS
	}

	private function delete_autologin_cookie(){
		$name = $this->cookie_pfix.'autologin';
		if(isset($_COOKIE[$name])) setcookie($name, '', 1);
	}
	
	private function savesession(){
		$json = json_encode([
			'user_id' => $this->user_id,
			'access' => $this->access
		]);
		
		$_SESSION[$this->session_var] = $json;
	}
	
	private function loadsession(){
		if(isset($_SESSION[$this->session_var])){
			$json = json_decode($_SESSION[$this->session_var]);
			$this->user_id = $json->user_id;
			$this->access = $json->access;
		} elseif(isset($_COOKIE[$this->cookie_pfix.'autologin'])){
			$this->open_db();
			$token = $this->db_conn->real_escape_string($_COOKIE[$this->cookie_pfix.'autologin']);
			$table = $this->db_pfix.'token';
			$sql = "SELECT user_id,token,expires<=NOW() as expired FROM $table WHERE token='$token'";
			$query = $this->db_conn->query($sql);
			if($query->num_rows!=1){
				$this->delete_autologin_cookie();
				return;
			}
			$rs = $query->fetch_object();
			if($rs->expired){
				$this->delete_autologin_cookie();
				$sql = "DELETE FROM $table WHERE expires<NOW()";
				$this->db_conn->query($sql);
				return;
			}
			$this->user_id = $rs->user_id;
			$this->update_access();
			$this->savesession();
		}
	}
	
	private function open_db(){
		if(!$this->db_conn){
			$this->db_conn = new mysqli('localhost',$this->db_user,$this->db_pass,$this->db_base);
			if($this->db_conn->connect_error) {
				die('SimpleAuth::open_db (Connection Error)');
			}
		}
	}
	
	public function user_id(){
		return $this->user_id;
	}
	
	public function error_string($code){
		if($code=='USERNAME_NOTSET')
			return "Username not set";
		else if($code=='USERNAME_UNKNOWN')
			return "Username unknown";
		else if($code=='USERNAME_INUSE')
			return "Username already taken";
		else if($code=='USER_NOT_LOGGED_IN')
			return "User is not logged in";
		else if($code=='PASSWORD_NOTSET')
			return "Password not set";
		else if($code=='PASSWORD_WRONG')
			return "Wrong password";
		else if($code=='PASSWORD_NOMATCH')
			return "Password does not match the confirm password";
		else
			return $code;
	}
}
?>