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
    public function __construct(string $key, string $vector)
    {
        $this->key = $key;
        $this->vector = $vector;
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
