<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm;

use Onion\Security\Encryption\Interfaces\Algorithm;

class A128CBC implements SymmetricAlgorithm
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

    public function getKey(): string
    {
        if (null === $this->key) {
            $secure = true;
            $this->key = openssl_random_pseudo_bytes(16, $secure);

            if (!$secure) {
                trigger_error('Generated key is not cryptographically secure', PHP_USER_WARNING);
            }
        }

        return $this->key;
    }
}
