<?php
namespace Onion\Security\Crypto\Strategy\Asymmetric;

use Onion\Security\Crypto\Interfaces\AlgorithmStrategyInterface;

abstract class Base implements AlgorithmStrategyInterface
{
    private $credential;
    private $key;
    private $secret;

    public function setCredential(string $credential): void
    {
        $this->credential = $credential;
    }

    public function setSecret(string $secret, string $key = ''): void
    {
        $this->secret = $secret;
        $this->key = $key;
    }


    public function getCredential(): string
    {
        return $this->credential;
    }

    public function getSecret(): string
    {
        return $this->secret;
    }

    public function getSecretKey(): string
    {
        return $this->key;
    }
}
