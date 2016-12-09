<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Interfaces;

/**
 * @internal
 */
interface Algorithm
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
     * Returns the name of the algorithm
     * @return string The name of the algorithm
     */
    public function getName(): string;

    /**
     * Returns the internal PHP identifier of the algorithm as string
     * consuming implementation should be responsible to typecast to
     * the desired type, since some require strings (hash, hmac_hash)
     * and some require integers (openssl_sign).
     */
    public function getAlgoIdentifier(): string;

    /**
     * Generate a cryptographic signature of the $data provided
     *
     * @param string $data url-safe Base64_encoded data to hash/encrypt
     *
     * @return string The hash/cyphertext
     */
    public function sign(string $data): string;

    /**
     * Verify the signature ot the $data provided
     *
     * @param string $data The data of which the signature should be validated
     * @param string $signature The signature against which to verify
     *
     * @return bool Whether or not the signature is valid for the data provided
     */
    public function verify(string $data, string $signature): bool;

    /**
     * Encrypt the provided data
     *
     * @param string $data Data to encrypt
     *
     * @param string The ciphertext
     */
    public function encrypt(string $data): string;

    /**
     * Decrypts the provided data
     *
     * @param string $data The ciphertext to decrypt
     *
     * @return string The decrypted data
     */
    public function decrypt(string $data): string;
}
