<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Interfaces;

interface AsymmetricEncryption extends EncryptionAlgorithm
{
    /**
     * (Case specific)
     * Encrypt with the private key and decrypt using the public key
     */
    const STRATEGY_PRIVATE_ENCRYPT = 1;

    /**
     * (Case specific)
     * Encrypt using the public key and decrypt using the private key
     */
    const STRATEGY_PUBLIC_ENCRYPT  = 2;
    
    /**
     * Retrun the public key used for encryption
     *
     * @return string The contents of the key
     */
    public function getPublicKey(): string;

    /**
     * Return the private key uesd for the encryption
     *
     * @return string The contents of the private key
     */
    public function getPrivateKey(): string;
}
