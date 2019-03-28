<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Interfaces;

interface EncryptionAlgorithm extends Algorithm
{
    /**
     * Encrypts the provided $plaintext
     *
     * @param string $plaintext The plaintext
     *
     * @return string The ciphertext
     */
    public function encrypt(string $plaintext, string &$tag, string $aad = ''): string;

    /**
     * Decrypts the provided $ciphertext
     *
     * @param string $ciphertext The ciphertext
     *
     * @return string the plaintext
     */
    public function decrypt(string $ciphertext, string $tag = '', string $aad = ''): string;
}
