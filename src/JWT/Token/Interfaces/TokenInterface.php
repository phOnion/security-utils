<?php
namespace Onion\Security\JWT\Token\Interfaces;

interface TokenInterface
{
    public const SERIALIZE_COMPACT = 1;
    public const SERIALIZE_JSON = 2;

    public function __toString(): string;

    public function addClaim(string $name, $value): void;
    public function getClaims(): array;

    public function addHeader(string $name, $value, bool $protected = false): void;
    public function getHeader(string $name);
    public function getHeaders(bool $protected = false): array;

    public function setSerializationType(int $type): void;
    public function getSerializationType(): int;
}
