<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm\Traits;

trait CommonRSLogic
{
    protected $publicKey;
    protected $privateKey;

    public function __construct(string $public, string $private)
    {
        if (!extension_loaded('openssl')) {
            throw new \RuntimeException(
                'OpenSSL extension is required to Generate RSA signatures'
            );
        }

        $this->publicKey = $public;
        $this->privateKey = $private;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    public function sign(string $token): string
    {
        $signature = null;
        openssl_sign($token, $signature, openssl_get_privatekey($this->getPrivateKey()), (int) $this->getAlogIdentifier());

        return $signature;
    }

    public function verify(string $data, string $signature): bool
    {
        return openssl_verify($data, $signature, openssl_get_publickey($this->getPublicKey()), (int) $this->getAlgoIdentifier());
    }
}
