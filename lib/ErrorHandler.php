<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
namespace TRP\SimpleAuth;

class ErrorHandler {
	/**
	 *
	 * Get the error message based on the provided error code.
	 *
	 * @param string $code Error code.
	 * @return string Error message.
	 */
	public static function error_string($code){
		if($code=='USER_NOT_FOUND')
			return "User not found with that id";
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
		else if($code=='PASSWORD_OLD_NOMATCH')
			return "Old password does not match the old confirm password";
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
}
