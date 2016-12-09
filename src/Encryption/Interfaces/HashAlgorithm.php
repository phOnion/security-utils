<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Interfaces;

interface HashAlgorithm extends Algorithm
{
    /**
     * Generate a cryptographic signature of the provided $data;
     *
     * @param string $data The data for which to generate the signature
     *
     * @return string The generated signature
     */
    public function sign(string $data): string;

    /**
     * Check if the provided $data matches the provided $signature
     *
     * @param string $data The data to check
     * @param string $signature The signature against which to verify
     *
     * @return bool Whether or not the signature belongs to the data 
     */
    public function verify(string $data, string $signature): bool;
}
