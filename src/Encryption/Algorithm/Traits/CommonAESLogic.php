<?php
declare(strict_types=1);
namespace Onion\Security\Encryption\Algorithm\Traits;

trait CommonAESLogic
{
    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $vector;

    private $signer;

    /**
     * @param string $key The key to use for encryption/decryption
     */
    public function __construct(string $key = null, string $vector = null)
    {
        $this->key = $key;
        $this->vector = $vector;
    }

    public function getInitializationVector(): string
    {
        if (null === $this->vector) {
            $secure = true;
            $this->vector = openssl_random_pseudo_bytes(
                openssl_cipher_iv_length($this->getAlgoIdentifier()),
                $secure
            );

            if (!$secure) {
                trigger_error('Generated IV is not cryptographically secure', PHP_USER_WARNING);
            }
        }

        return $this->vector;
    }

    public function encrypt(string $data): string
    {
        return openssl_encrypt($data, $this->getAlgoIdentifier(), $this->key, OPENSSL_RAW_DATA, $this->vector);
    }

    public function decrypt(string $data): string
    {
        return openssl_decrypt($data, $this->getAlgoIdentifier(), $this->key, OPENSSL_RAW_DATA, $this->vector);
    }


    public function sign(string $data): string
    {
        throw new \RuntimeException('Can\'t use "' . $this->getName() . '" for signing.');
    }
}
