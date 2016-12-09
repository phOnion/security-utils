<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm\Traits;

trait CommonRSLogic
{
    protected $publicKey;
    protected $privateKey;
    protected $strategy;

    public function __construct(string $public, string $private, int $strategy = self::STRATEGY_PRIVATE_ENCRYPT)
    {
        if (!extension_loaded('openssl')) {
            throw new \RuntimeException(
                'OpenSSL extension is required to do asymetric encryption'
            );
        }

        $this->publicKey = openssl_pkey_get_public($public);
        if ($this->publicKey === false) {
            throw new \InvalidArgumentException('Inavlid public key');
        }
        $this->privateKey = openssl_pkey_get_private($private);
        if ($this->privateKey === false) {
            throw new \InvalidArgumentException('Inavlid private key');
        }

        $this->strategy = $strategy;
    }

    public function encrypt(string $data): string
    {
        $cyphertext = null;
        if ($this->strategy === self::STRATEGY_PRIVATE_ENCRYPT) {
            openssl_private_encrypt($data, $cyphertext, $this->privateKey);
        }

        if ($this->strategy === self::STRATEGY_PUBLIC_ENCRYPT) {
            openssl_public_encrypt($data, $cyphertext, $this->publicKey);
        }

        return $cyphertext;
    }

    public function decrypt(string $data): string
    {
        $decrypted = null;

        if ($this->strategy === self::STRATEGY_PRIVATE_ENCRYPT) {
            openssl_public_decrypt($data, $decrypted, $this->publicKey);
        }

        if ($this->strategy === self::STRATEGY_PUBLIC_ENCRYPT) {
            openssl_private_decrypt($data, $decrypted, $this->privateKey);
        }

        return $decrypted;
    }

    public function sign(string $token): string
    {
        $signature = null;
        openssl_sign($token, $signature, $this->privateKey, (int) $this->getAlogIdentifier());

        return $signature;
    }
}
