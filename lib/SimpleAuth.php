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
	
	function __construct($options = []){
		if(isset($options['db_host'])) $this->db_host = $options['db_host'];
		if(isset($options['db_user'])) $this->db_user = $options['db_user'];
		if(isset($options['db_pass'])) $this->db_pass = $options['db_pass'];
		if(isset($options['db_base'])) $this->db_base = $options['db_base'];
		if(isset($options['db_pfix'])) $this->db_pfix = $options['db_pfix'];
		if(isset($options['session_var'])) $this->session_var = $options['session_var'];
		if(isset($options['lifetime'])) $this->lifetime = $options['lifetime'];
		
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
	
	public function login($username,$password){
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
		
		$user_id = $rs->id;
		$table = $this->db_pfix.'access';
		$sql = "SELECT permission FROM $table WHERE user_id='$user_id'";
		$query = $this->db_conn->query($sql);
		while($rs = $query->fetch_object()){
			$this->add_access($rs->permission,false);
		}
		
		$this->user_id = $user_id;		
		$this->savesession();
		
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