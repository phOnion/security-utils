<?php
namespace Onion\Security\JWT\Token\Interfaces;

use Onion\Security\Encryption\Interfaces\AsymmetricAlgorithm;
use Onion\Security\Encryption\Interfaces\SymmetricAlgorithm;


interface EncryptedTokenInterface extends TokenInterface
{
    public function setEncryptionAlgorithm(AsymmetricAlgorithm $algo): void;
    public function addKeyEncryptionAlgorithm(SymmetricAlgorithm $algo): void;
}
