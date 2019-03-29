<?php
namespace Onion\Security\Crypto\Strategy;

use Onion\Security\Crypto\Interfaces\AsymmetricAlgorithmInterface;
use Onion\Security\Crypto\Strategy\Asymmetric\Base;


class Aes extends Base implements AsymmetricAlgorithmInterface
{
    private $size;
    private $mode;

    public function __construct(int $size = 256, string $mode = 'CBC')
    {
        if (!in_array($size, [128, 192, 256], true)) {
            throw new \RuntimeException("Provided size '{$size}' is not a supported size for AES");
        }

        $mode = strtoupper($mode);

        if (!in_array($mode, ['CBC', 'CFB', 'OFB'], true)) {
            throw new \RuntimeException("Provided mode '{$mode}' is not supported mode for AES");
        }
        $this->size = $size;
        $this->mode = $mode;

        if (!in_array($this->getAlgorithmIdentifier(), openssl_get_cipher_methods(true))) {
            throw new \RuntimeException(
                "Algorithm '{$this->getAlgorithmIdentifier()}' is not supported by your platform"
            );
        }
    }

    public function getAlgorithmIdentifier(): string
    {
        return "aes-{$this->size}-{$this->mode}";
    }
}
