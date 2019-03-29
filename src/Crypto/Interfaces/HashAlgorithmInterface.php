<?php
namespace Onion\Security\Crypto\Interfaces;

interface HashAlgorithmInterface
{
    public function sign(string $data): string;
    public function verify(string $data, string $hash): bool;
}
