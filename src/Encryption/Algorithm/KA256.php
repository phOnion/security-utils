<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithms;

use Onion\Security\Encryption\Interfaces\SymmetricAlgorithm;
use Onion\Security\Encryption\Algorithm\Traits\CommonAESLogic;

class KA256 extends \AESKW\AESKW256 implements SymmetricAlgorithm
{
    private $key;

    use CommonAESLogic;

    public function __construct(string $kek = '')
    {
        parent::__construct($this->getInitializationVector());
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

    public function encrypt(string $data): string
    {
        return $this->wrapPad($data, $this->getKey());
    }

    public function decrypt(string $data): string
    {
        return $this->unwrapPad($data, $this->getKey());
    }
}
