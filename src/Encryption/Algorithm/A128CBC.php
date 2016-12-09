<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm;

use Onion\Security\Encryption\Interfaces\Algorithm;

class A128CBC implements Algorithm
{
    use Traits\CommonAESLogic;

    public function getName(): string
    {
        return 'A128CBC';
    }

    public function getAlgoIdentifier(): string
    {
        return 'AES-128-CBC';
    }
}
