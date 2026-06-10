<?php
declare(strict_types=1);

namespace TRP\SimpleAuth;

enum TfaStatus: string {
	case DISABLED = 'disabled';
	case ACTIVE = 'active';
	case PENDING = 'pending';
	case UNUSED = 'unused';
}
