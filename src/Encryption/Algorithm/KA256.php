<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithms;

use Onion\Security\Encryption\Interfaces\SymmetricEncryption;

class KA256 extends AESKW\AESKW256
{
    private $key;

    public function __construct(string $kek = '')
    {
        parent::__construct();
        $this->key = $kek;
    }

    public function getName(): string
    {
        return 'A256KW';
    }

    public function getAlgoIdentifier(): string
    {
        return $this->_cypherMethod();
    }

    public function getKey(): string
    {
        if (null === $this->key) {
            $key = openssl_random_pseudo_bytes(32);
        }
        return $this->key;
    }

    public function getInitializationVector(): string
    {
        trigger_error('Algorithm A256KW does not use IV', PHP_USER_NOTICE);
        return '';
    }

    public function encrypt(string $data): string
    {
        return $this->wrap($data, $this->getKey());
    }

    public function decrypt(string $ciphertext): string
    {
        return $this->unwrap($data, $this->getKey());
    }
}
