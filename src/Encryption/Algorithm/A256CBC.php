<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm;

use Onion\Security\Encryption\Interfaces\Algorithm;

class A256CBC implements SymmetricAlgorithm
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

    public function getKey(): string
    {
        if (null === $this->key) {
            $secure = true;
            $this->key = openssl_random_pseudo_bytes(32, $secure);

            if (!$secure) {
                trigger_error('Generated key is not crypto secure', PHP_USER_WARNING);
            }
        }

        return $this->key;
    }
}
