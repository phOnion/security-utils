<?php
namespace Onion\Security\JWT\Token\Interfaces;

use Onion\Security\Encryption\Interfaces\HashAlgorithm;


interface SignatureTokenInterface extends TokenInterface
{
    public function addSignatureAlgorithm(HashAlgorithm $algo, array $headers = []): void;
    public function setPayload(string $payload): void;
}
