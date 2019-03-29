<?php
namespace Onion\Security\Crypto\Interfaces;

interface WrappingAlgorithmInterface
{
    public function wrap(string $key): string;
    public function unwrap(string $wrapped): string;
}
