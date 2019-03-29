<?php
namespace Onion\Security\JWT\Token;

use Onion\Security\JWT\Token\Interfaces\EncryptedTokenInterface;
use Onion\Security\Encryption\Interfaces\AsymmetricAlgorithm;
use Onion\Security\Encryption\Interfaces\SymmetricAlgorithm;


class JWE extends JWT implements EncryptedTokenInterface
{
    private $encryption = [];
    private $keyEncryption = [];

    private $payload;

    public function addKeyEncryptionAlgorithm(SymmetricAlgorithm $algo): void
    {
        $this->keyEncryption[] = $algo;
    }

    public function setEncryptionAlgorithm(AsymmetricEncryption $algo): void
    {
        $this->encryption[] = $algo;
    }

    public function setPayload(string $payload): void
    {
        $this->payload = $payload;
    }

    public function __toString(): string
    {
        if ($this->getSerializationType() === self::SERIALIZE_COMPACT) {
            /** @var SymmetricAlgorithm $kw */
            $kw = current($this->keyEncryption);
            /** @var AsymmetricAlgorithm $encryption */
            $encryption = current($this->encryption);
            $encodedHeaders = base64_urlencode(json_encode(array_merge($this->getHeaders(), [
                'enc' => $encryption->getName(),
                'alg' => $kw->getName(),
            ])));

            $payload = $encodedHeaders;
            $aad = $encodedHeaders;
            $payload .= '.';
            $payload .= base64_urlencode($kw->encrypt($encryption->getPublicKey(), $tag, $aad));
            $payload .= '.';
            $payload .= base64_urlencode($kw->getInitializationVector());
            $payload .= '.';
            $payload .= base64_urlencode($aad);

            $cipherText = $encryption->encrypt($this->payload, $tag, $aad);

            $payload .= '.';
            $payload .= base64_urlencode($tag)
        }

        return '';
    }
}
