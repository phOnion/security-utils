<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm;

use Onion\Security\Encryption\Interfaces\Algorithm;

class A256CBC implements Algorithm
{
    use Traits\CommonAESLogic;
    
    public function getName(): string
    {
        return 'A256CBC';
    }

    public function getAlgoIdentifier(): string
    {
        return 'AES-256-CBC';
    }
}
