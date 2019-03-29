<?php
namespace Onion\Security\Crypto\Interfaces;

interface SymmetricAlgorithmInterface extends AlgorithmStrategyInterface
{
    public function setCredential(string $credential): void;
    public function getCredential();
}
