<?php

declare(strict_types=1);

namespace Fschmtt\Keycloak\Enum;

enum BruteForceStrategy: string implements Enum
{
    case LINEAR = 'LINEAR';
    case MULTIPLE = 'MULTIPLE';
}
