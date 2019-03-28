<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm;

use Onion\Security\Encryption\Interfaces\Algorithm;
use Onion\Security\Encryption\Interfaces\HashAlgorithm;

class HS512 implements Algorithm, HashAlgorithm
{
    use Traits\CommonHSLogic;

    public function getName(): string
    {
        return 'HS512';
    }

    public function getAlgoIdentifier(): string
    {
        return 'sha512';
    }
}
