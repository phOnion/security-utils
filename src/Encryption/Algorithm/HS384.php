<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm;

use Onion\Security\Encryption\Interfaces\Algorithm;

class HS384 implements Algorithm
{
    use Traits\CommonHSLogic;

    public function getName(): string
    {
        return 'HS384';
    }

    public function getAlgoIdentifier(): string
    {
        return 'sha384';
    }
}
