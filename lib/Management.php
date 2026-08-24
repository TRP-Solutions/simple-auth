<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

namespace TRP\SimpleAuth;

Class Management {
	private int $id;
	private string $username;
	private string $password;
	private array $access = [];
	private string $confirmation;
	private string $tfa_secret;
	private TfaStatus $tfa_status;

	public function __construct(int $id) {
		$this->id = $id;
		$table = Config::$db_pfix.'user';
		$sql = "SELECT `username`,`password`,`confirmation`,`tfa_secret`,`tfa_status` FROM `$table` WHERE `id`='$this->id'";
		$query = Config::$db_conn->query($sql);
		if($query->num_rows!=1){
			throw new \Exception('USER_NOT_FOUND');
		}
		while($rs = $query->fetch_object()){
			$this->username = $rs->username;
			$this->password = $rs->password;
			$this->confirmation = $rs->confirmation?? "";
			$this->tfa_secret = $rs->tfa_secret ?? "";
			$this->tfa_status = $rs->tfa_status !== null
				? TfaStatus::tryFrom($rs->tfa_status)
				: TfaStatus::DISABLED;
		}

		$table = Config::$db_pfix.'access';
		$sql = "SELECT `permission` FROM `$table` WHERE `user_id`='$this->id'";
		$query = Config::$db_conn->query($sql);
		while($rs = $query->fetch_object()){
			if(in_array($rs->permission, Config::$require_tfa, true) && !$this->tfa_status == TfaStatus::ACTIVE) continue;

			if(($key = array_search($rs->permission,$this->access)) === false){
				$this->access[] = $rs->permission;
			}
		}
	}


	public static function create(string $username) : int {
		if(!$username){
			throw new \Exception('USERNAME_NOTSET');
		}

		$username = trim(Config::$db_conn->real_escape_string($username));
		$table = Config::$db_pfix.'user';
		$sql = "SELECT `id` FROM `$table` WHERE `username`='$username'";
		$query = Config::$db_conn->query($sql);
		if($query->num_rows==1){
			throw new \Exception('USERNAME_INUSE');
		}

		$sql = "INSERT INTO `$table` (`username`) VALUES ('$username')";
		Config::$db_conn->query($sql);
		return (int) Config::$db_conn->insert_id;
	}

	public static function disable(int $id) : void {
		$table = Config::$db_pfix.'access';
		$sql = "DELETE FROM `$table` WHERE `user_id`='$id'";
		Config::$db_conn->query($sql);

		$table = Config::$db_pfix.'token';
		$sql = "DELETE FROM `$table` WHERE `user_id`='$id'";
		Config::$db_conn->query($sql);

		$table = Config::$db_pfix.'user';
		$sql = "UPDATE `$table` SET `password`='',`confirmation`='' WHERE `id`='$id'";
		Config::$db_conn->query($sql);
	}

	public function access(string ...$access) : bool {
		foreach ($access as $permission) {
			if (!in_array($permission, $this->access, true)) {
				return false;
			}
		}

		return true;
	}


	public function get_id(): int {
		return $this->id;
	}

	public function set_id(int $id) : void {
		$this->id = $id;
	}

	public function get_username() : string {
		return $this->username;
	}

	public function set_username(string $username) : void {
		$this->username = $username;

		$table = Config::$db_pfix . 'user';
		$stmt = Config::$db_conn->prepare("UPDATE `$table` SET `username` = ? WHERE `user_id` = ?");
		$stmt->bind_param("si", $username, $this->id);
		$stmt->execute();
	}

	public function get_password() : string {
		return $this->password;
	}

	public function update_password(string $password, string $old_password, ?string $repeat_password = null, ?string $repeat_old_password = null) : void {
		if($repeat_old_password && $old_password !== $repeat_old_password){
			throw new \Exception('PASSWORD_OLD_NOMATCH');
		}

		if($repeat_password && $this->password !== $repeat_password){
			throw new \Exception('PASSWORD_NOMATCH');
		}

		if(!password_verify($old_password, $this->password)){
			throw new \Exception('PASSWORD_WRONG');
		}
		$password = password_hash($password, PASSWORD_DEFAULT);
		$this->password = $password;

		$table = Config::$db_pfix . 'user';
		$stmt = Config::$db_conn->prepare("UPDATE `$table` SET `password` = ? WHERE `id` = ?");
		$stmt->bind_param("si", $password, $this->id);
		$stmt->execute();
	}

	public function set_password(string $password) : void {
		$password = password_hash($password, PASSWORD_DEFAULT);
		$this->password = $password;

		$table = Config::$db_pfix . 'user';
		$stmt = Config::$db_conn->prepare("UPDATE `$table` SET `password` = ? WHERE `id` = ?");
		$stmt->bind_param("si", $password, $this->id);
		$stmt->execute();
	}


	public function get_access() : array {
		return $this->access;
	}

	public function set_access(array $access) : void {
		$access = array_values(array_unique($access));
		$this->access = $access;

		$table = Config::$db_pfix . 'user_access';
		$stmt = Config::$db_conn->prepare("SELECT `access` FROM `$table` WHERE `user_id` = ?");
		$stmt->bind_param("i", $this->id);
		$stmt->execute();

		$result = $stmt->get_result();

		$current = [];
		while ($row = $result->fetch_assoc()) {
			$current[] = $row['access'];
		}

		$toAdd = array_diff($access, $current);
		$toRemove = array_diff($current, $access);

		$insert = Config::$db_conn->prepare("INSERT INTO `$table` (`user_id`, `access`) VALUES (?, ?)");

		foreach ($toAdd as $permission) {
			$insert->bind_param("is", $this->id, $permission);
			$insert->execute();
		}

		$delete = Config::$db_conn->prepare("DELETE FROM `$table` WHERE `user_id` = ? AND `access` = ?");

		foreach ($toRemove as $permission) {
			$delete->bind_param("is", $this->id, $permission);
			$delete->execute();
		}
	}

	public function add_access(string $access) : void {
		if (in_array($access, $this->access, true)) {
			return;
		}

		$this->access[] = $access;

		$table = Config::$db_pfix . 'user_access';
		$stmt = Config::$db_conn->prepare("INSERT INTO `$table` (`user_id`, `access`) VALUES (?, ?)");
		$stmt->bind_param("is", $this->id, $access);
		$stmt->execute();
	}

	public function remove_access(string $access) : void {
		$this->access = array_values(
			array_filter(
				$this->access,
				fn($a) => $a !== $access
			)
		);

		$table = Config::$db_pfix . 'user_access';
		$stmt = Config::$db_conn->prepare("DELETE FROM `$table` WHERE `user_id` = ? AND `access` = ?");
		$stmt->bind_param("is", $this->id, $access);
		$stmt->execute();
	}

	public function get_confirmation() : string {
		return $this->confirmation;
	}

	public function set_confirmation(string $confirmation) : void {
		$this->confirmation = $confirmation;

		$table = Config::$db_pfix . 'user';
		$stmt = Config::$db_conn->prepare("UPDATE `$table` SET `confirmation` = ? WHERE `id` = ?");
		$stmt->bind_param("si", $confirmation, $this->id);
		$stmt->execute();
	}

	public function get_tfa_secret() : string {
		return $this->tfa_secret;
	}

	public function set_tfa_secret(string $tfa_secret) : void {
		$this->tfa_secret = $tfa_secret;

		$table = Config::$db_pfix . 'user';
		$stmt = Config::$db_conn->prepare("UPDATE `$table` SET `tfa_secret` = ? WHERE `id` = ?");
		$stmt->bind_param("si", $tfa_secret, $this->id);
		$stmt->execute();
	}
	public function get_tfa_status() : TfaStatus {
		return $this->tfa_status;
	}

	public function set_tfa_status(TfaStatus $tfa_status) : void {
		$this->tfa_status = $tfa_status;

		$status = $tfa_status->name;

		$table = Config::$db_pfix . 'user';
		$stmt = Config::$db_conn->prepare("UPDATE `$table` SET `tfa_status` = ? WHERE `id` = ?");
		$stmt->bind_param("si", $status, $this->id);
		$stmt->execute();
	}
}
