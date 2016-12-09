<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Interfaces;

interface Delegate
{
    public function getEncrypterName(): string;
    public function getSignerName(): string;

    public function hasEncrypter(): bool;
    public function hasSigner(): bool;

    public function encrypt(string $data): string;
    public function decrypt(string $data): string;
    public function sign(string $data): string;
    public function verify(string $data, string $signature): bool;
}
