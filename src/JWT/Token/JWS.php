<?php
namespace Onion\Security\JWT\Token;

use Onion\Security\Encryption\Interfaces\HashAlgorithm;
use Onion\Security\JWT\Token\Interfaces\SignatureTokenInterface;

class JWS extends JWT implements SignatureTokenInterface
{
    /** @var HashAlgorithm[] $signatureAlgorithms */
    private $signatureAlgorithms = [];
    private $protected = [];
    private $payload;

    public function __construct(HashAlgorithm $algo)
    {
        parent::__construct($algo);
        $this->addSignatureAlgorithm($algo, []);
    }

    public function addSignatureAlgorithm(HashAlgorithm $algo, array $headers = [], array $protected = []): void
    {
        $this->signatureAlgorithms[] = [$algo, $headers, $protected];
    }

    public function setPayload(string $payload): void
    {
        $this->payload = $payload;
    }

    public function __toString(): string
    {
        if ($this->getSerializationType() === self::SERIALIZE_COMPACT) {
            /** @var HashAlgorithm $algo */
            $algo = current($this->signatureAlgorithms)[0];

            $payload = base64_urlencode(json_encode(array_merge($this->getHeaders(), [
                'alg' => $algo->getName(),
            ])));
            $payload .= '.';
            $payload .= base64_urlencode($this->payload);

            return $payload .= '.' . base64_urlencode($algo->sign($payload));
        }

        if ($this->getSerializationType() === self::SERIALIZE_JSON) {
            $payload = base64_urlencode($this->payload);
            $signatures = [];
            foreach ($this->signatureAlgorithms as $extra) {
                list($algo, $headers, $protected) = $extra;

                $protectedHeaders = base64_urlencode(json_encode(array_merge($this->getHeaders(true), $protected, [
                    'alg' => $algo->getName(),
                ])));

                $signature = [
                    'protected' => $protectedHeaders,
                    'header' => array_merge($this->getHeaders(), $headers),
                    'signature' => base64_urlencode($algo->sign("{$protectedHeaders}.{$payload}")),
                ];

                $signatures[] = $signature;
            }

            return json_encode([
                'payload' => $payload,
                'signatures' => $signatures,
            ]);
        }

        return '';
    }
}
