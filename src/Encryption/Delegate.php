<?php
declare(strict_types=1);
namespace Onion\Security\Encryption;

class Delegate implements Interfaces\Delegate
{
    /**
     * @var Algorithm
     */
    private $signer;

    /**
     * @var Algorithm
     */
    private $encrypter;

    public function __construct(Interfaces\Algorithm $signer = null, Interfaces\Algorithm $encrypter = null)
    {
        $this->signer = $signer;
        $this->encrypter = $encrypter;
    }

    public function hasEncrypter(): bool
    {
        return $this->encrypter instanceof Interfaces\Algorithm;
    }

    public function hasSigner(): bool
    {
        return $this->signer instanceof Interfaces\Algorithm;
    }

    public function getEncrypterName(): string
    {
        if (!$this->hasEncrypter()) {
            throw new \LogicException('Unable to get encryption algorithm name.');
        }

        return $this->encrypter->getName();
    }

    public function getSignerName(): string
    {
        if (!$this->hasSigner()) {
            throw new \LogicException('Unable to get signature algorithm name.');
        }

        return $this->signer->getName();
    }

    public function encrypt(string $data): string
    {
        if (!$this->hasEncrypter()) {
            throw new \LogicException(
                'Unable to encrypt data, no encryption algorithm provided.'
            );
        }

        return $this->encrypter->encrypt($data);
    }

    public function decrypt(string $data): string
    {
        if (!$this->hasEncrypter()) {
            throw new \LogicException(
                'Unable to decrypt data, no encryption algorithm provided.'
            );
        }

        return $this->encrypter->decrypt($data);
    }

    public function sign(string $data): string
    {
        if (!$this->hasSigner()) {
            throw new \LogicException(
                'Unable to generate signature, no signature algorithm provided'
            );
        }

        return $this->signer->sign($data);
    }

    public function verify(string $data, string $signature): bool
    {
        if (!$this->hasSigner()) {
            throw new \LogicException('Unable to verify signature, no signer available');
        }

        return $this->signer->verify($data, $signature);
    }
}
