<?php
namespace Onion\Security\Crypto\Interfaces;

use Onion\Security\Crypto\Interfaces\EncryptedPayloadInterface;

interface EncryptionAlgorithmInterface
{
    public function encrypt(string $data): EncryptedPayloadInterface;
    public function decrypt(EncryptedPayloadInterface $payload): string;
}
