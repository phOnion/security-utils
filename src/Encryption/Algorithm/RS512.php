<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm;

use Onion\Security\Encryption\Interfaces\Algorithm;

class RS512 implements Algorithm
{
    use Traits\CommonRSLogic;

    public function getName(): string
    {
        return 'RS512';
    }

    public function getAlgoIdentifier(): string
    {
        return (string) OPENSSL_ALGO_SHA512;
    }
}
