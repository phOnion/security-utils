<?php
namespace Onion\Security\Crypto\Interfaces;

interface EncryptedPayloadInterface
{
    public function getResult(bool $base64 = true): string;
    public function getAad(): string;
    public function getTag(): string;
}
