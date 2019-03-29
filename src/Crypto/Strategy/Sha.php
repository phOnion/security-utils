<?php
namespace Onion\Security\Crypto\Strategy;

use Onion\Security\Crypto\Interfaces\AsymmetricAlgorithmInterface;
use Onion\Security\Crypto\Strategy\Asymmetric\Base;


class Sha extends Base implements AsymmetricAlgorithmInterface
{
    private $size;

    public function __construct(int $size = 512)
    {
        if (!in_array($size, [256, 384, 512], true)) {
            throw new \RuntimeException("Provided size '{$size}' is not supported size for SHA");
        }
        $this->size = $size;

        if (!in_array($this->getAlgorithmIdentifier(), openssl_get_md_methods(true))) {
            throw new \RuntimeException(
                "Algorithm '{$this->getAlgorithmIdentifier()}' is not supported by your platform"
            );
        }
    }

    public function getAlgorithmIdentifier(): string
    {
        return "sha-{$this->size}";
    }
}
