<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Interfaces;

/**
 * @internal
 */
interface Algorithm
{
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
}
