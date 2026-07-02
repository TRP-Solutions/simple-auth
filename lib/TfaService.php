<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

namespace TRP\SimpleAuth;
require_once __DIR__ . '/TfaAuthenticator.php';
require_once __DIR__ . '/TfaQRCode.php';

class TfaService {
	private static ?\TRP\SimpleAuth\TfaAuthenticator $ga = null;
	public static function create_tfa(Management $user): string
	{
		$secret = $user->get_tfa_secret();

		if ($user->get_tfa_status() !== TfaStatus::ACTIVE) {
			$secret = self::get_tfa()->createSecret();

			$user->set_tfa_secret($secret);
			$user->set_tfa_status(TfaStatus::PENDING);
		}

		$issuer = Config::$tfa_issuer;
		$username = $user->get_username();

		$otpauth = sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s',
			rawurlencode($issuer),
			rawurlencode($username),
			$secret,
			rawurlencode($issuer)
		);

		$generator = new \TRP\SimpleAuth\TfaQRCode($otpauth, null);

		$image = $generator->render_image();

		ob_start();
		imagepng($image);
		$png = ob_get_clean();
		imagedestroy($image);

		return 'data:image/png;base64,' . base64_encode($png);
	}

	public static function delete_tfa(Management $user) : void {
		$user->set_tfa_secret("");
		$user->set_tfa_status(TfaStatus::UNUSED);
		Session::$has_tfa = false;
		Session::update_access();
		Session::save_session();
	}

	public static function validate_tfa_code(Management $user, string $code) : bool {
		if ($user->get_tfa_status() === TfaStatus::PENDING) {
			if (!$user->get_tfa_secret()) {
				$user->set_tfa_status(TfaStatus::DISABLED);
				return false;
			}
			$is_valid = self::get_tfa()->verifyCode($user->get_tfa_secret(), $code, 2);

			if($is_valid){
				$user->set_tfa_status(TfaStatus::ACTIVE);
				Session::$has_tfa = true;
				Session::update_access();
				Session::save_session();
			}
			return $is_valid;
		}

		return self::get_tfa()->verifyCode($user->get_tfa_secret(), $code, 2);
	}

	private static function get_tfa() : \TRP\SimpleAuth\TfaAuthenticator {
		if (!self::$ga) {
			self::$ga = new \TRP\SimpleAuth\TfaAuthenticator();
		}
		return self::$ga;
	}
}
