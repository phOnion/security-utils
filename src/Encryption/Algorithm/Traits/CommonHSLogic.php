<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm\Traits;

trait CommonHSLogic
{
    private $key;

    public function __construct($secret)
    {
        $this->key = $secret;
    }

    public function encrypt(string $data): string
    {
        return $data;
    }

    public function decrypt(string $data): string
    {
        return $data;
    }

    public function sign(string $data): string
    {
        return hash_hmac($this->getAlgoIdentifier(), $data, $this->key, true);
    }
}
