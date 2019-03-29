<?php
namespace Onion\Security\Crypto;

use Onion\Security\Crypto\Interfaces\HashAlgorithmInterface;
use Onion\Security\Crypto\Interfaces\SymmetricAlgorithmInterface;

class Hmac implements HashAlgorithmInterface
{
    private const ALGORITHM_MAP = [
        OPENSSL_ALGO_SHA256 => 'sha256',
        OPENSSL_ALGO_SHA384 => 'sha384',
        OPENSSL_ALGO_SHA512 => 'sha512',
    ];

    private $algo;

    public function __construct(SymmetricAlgorithmInterface $algo)
    {
        $this->algo = $algo;
    }

    public function sign(string $data): string
    {
        return hash_hmac(
            self::ALGORITHM_MAP[$this->algo->getAlgorithmIdentifier()],
            $data,
            $this->algo->getCredential(),
            true
        );
    }

    public function verify(string $data, string $hash): bool
    {
        return hash_equals($hash, $this->sign($data));
    }
}
