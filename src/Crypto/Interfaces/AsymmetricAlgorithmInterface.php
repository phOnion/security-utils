<?php
namespace Onion\Security\Crypto\Interfaces;

interface AsymmetricAlgorithmInterface extends SymmetricAlgorithmInterface
{
    public function setSecret(string $secret, string $key = ''): void;
    public function getSecret(): string;
    public function getSecretKey(): string;
}
