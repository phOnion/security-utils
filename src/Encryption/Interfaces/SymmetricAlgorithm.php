<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Interfaces;

interface SymmetricAlgorithm extends EncryptionAlgorithm
{
    /**
     * Retrieve the key used for encryption
     *
     * @return string The key
     */
    public function getKey(): string;

    /**
     * Retrieve the initialization vector (iv) used for the encryption
     *
     * @var string The iv
     */
    public function getInitializationVector(): string;
}
