<?php
namespace Onion\Security\Crypto;

use Onion\Security\Crypto\Interfaces\AsymmetricAlgorithmInterface;
use Onion\Security\Crypto\Interfaces\EncryptedPayloadInterface;
use Onion\Security\Crypto\Interfaces\EncryptionAlgorithmInterface;
use Onion\Security\Crypto\Interfaces\HashAlgorithmInterface;

class Asymmetric implements HashAlgorithmInterface, EncryptionAlgorithmInterface
{
    const ENCRYPT_PRIVATE = 1;
    const ENCRYPT_PUBLIC = 2;

    /** @var AsymmetricAlgorithmInterface */
    private $algo;
    private $mode;

    public function __construct(AsymmetricAlgorithmInterface $algo, int $mode = self::ENCRYPT_PRIVATE)
    {
        $this->algo = $algo;
        $this->mode = $mode === self::ENCRYPT_PRIVATE ? self::ENCRYPT_PRIVATE : self::ENCRYPT_PUBLIC;
    }

    public function sign(string $data): string
    {
        $signature = '';

        $success = openssl_sign(
            $data,
            $signature,
            openssl_pkey_get_private($this->algo->getSecret(), $this->algo->getSecretKey()),
            $this->algo->getAlgorithmIdentifier()
        );

        if (!$success) {
            throw new \RuntimeException(
                'Generating signature failed: ' .
                openssl_error_string()
            );
        }

        return $signature;
    }

    public function verify(string $data, string $hash): bool
    {
        $result = openssl_verify(
            $data,
            $hash,
            openssl_pkey_get_public($this->algo->getCredential()),
            $this->algo->getAlgorithmIdentifier()
        );

        if ($result === -1) {
            throw new \RuntimeException(
                'Validating signature failed: ' .
                openssl_error_string()
            );
        }

        return $result === 1;
    }

    public function encrypt(string $data): EncryptedPayloadInterface
    {
        $encrypted = '';

        if ($this->mode === self::ENCRYPT_PUBLIC) {
            $result = openssl_public_encrypt($data, $encrypted, openssl_pkey_get_public($this->algo->getCredential()), OPENSSL_PKCS1_OAEP_PADDING);
        } else {
            $result = openssl_private_encrypt($data, $encrypted, openssl_pkey_get_private($this->algo->getSecret(), $this->algo->getSecretKey()), OPENSSL_PKCS1_OAEP_PADDING);
        }

        if (!$result) {
            throw new \RuntimeException(
                'Encryption failed: ' . openssl_error_string()
            );
        }

        return new CryptoObject($encrypted);
    }

    public function decrypt(EncryptedPayloadInterface $object): string
    {
        $decrypted = '';
        if ($this->mode === self::ENCRYPT_PUBLIC) {
            $result = openssl_private_decrypt($object->getResult(false), $decrypted, openssl_pkey_get_private($this->algo->getSecret(), $this->algo->getSecretKey()), OPENSSL_PKCS1_OAEP_PADDING);
        } else {
            $result = openssl_public_decrypt($object->getResult(false), $decrypted, openssl_pkey_get_public($this->algo->getCredential()), OPENSSL_PKCS1_OAEP_PADDING);
        }

        if (!$result) {
            throw new \RuntimeException(
                'Decryption failed: ' . openssl_error_string()
            );
        }

        return $decrypted;
    }
}
