<?php
namespace Onion\Security\Crypto;

use Onion\Security\Crypto\Interfaces\EncryptedPayloadInterface;


class CryptoObject implements EncryptedPayloadInterface
{
    private $result;
    private $aad;
    private $tag;

    public function __construct(string $result, string $aad = '', string $tag = '')
    {
        $this->result = $result;
        $this->aad = $aad;
        $this->tag = $tag;
    }

    public function getResult(bool $base64 = true): string
    {
        return $base64 ?
            base64_encode($this->result) : $this->result;
    }

    public function getAad(): string
    {
        return $this->aad;
    }

    public function getTag(): string
    {
        return $this->tag;
    }
}
