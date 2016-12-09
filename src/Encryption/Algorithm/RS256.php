<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm;

use Onion\Security\Encryption\Interfaces\Algorithm;

class RS256 implements Algorithm
{
    use Traits\CommonRSLogic;

    public function getName(): string
    {
        return 'RS256';
    }

    public function getAlgoIdentifier()
    {
        return (string) OPENSSL_ALGO_SHA256;
    }
}
