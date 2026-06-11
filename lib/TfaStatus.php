<?php
/*
SimpleAuth is licensed under the Apache License 2.0 license
https://github.com/TRP-Solutions/simple-auth/blob/master/LICENSE
*/
declare(strict_types=1);

namespace TRP\SimpleAuth;

enum TfaStatus: string {
	case DISABLED = 'disabled';
	case ACTIVE = 'active';
	case PENDING = 'pending';
	case UNUSED = 'unused';
}
