<?php
namespace Onion\Security\JWT\Token;

use Onion\Security\JWT\Token\Interfaces\TokenInterface;
use Onion\Security\Encryption\Interfaces\HashAlgorithm;


class JWT implements TokenInterface
{
    private $headers = [];
    private $protected = [];

    private $claims = [];
    private $algo;
    private $mode = self::SERIALIZE_COMPACT;

    public function __construct(HashAlgorithm $algo)
    {
        $this->algo = $algo;
    }

    public function addClaim(string $name, $value): void
    {
        $this->claims[$name] = $value;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function addHeader(string $name, $value, bool $protected = false): void
    {
        if ($protected) {
            $this->protected[$name] = $value;
        } else {
            $this->headers[$name] = $value;
        }
    }

    public function getHeader(string $name, bool $protected = false)
    {
        return (!$protected ? $this->headers : $this->protected)[$name] ?? null;
    }

    public function getHeaders(bool $protected = false): array
    {
        if ($protected) {
            return $this->protected;
        }

        return $this->headers;
    }

    public function setSerializationType(int $type): void
    {
        $this->mode = $type;
    }

    public function getSerializationType(): int
    {
        return $this->mode;
    }

    public function __toString(): string
    {
        $payload = base64_urlencode(json_encode($this->claims));
        $payload .= '.';
        $payload .= base64_urlencode(json_encode($this->headers));
        $payload .= '.' . $this->algo->sign($payload);

        return $payload;
    }

    protected function getAlgorithm(): HashAlgorithm
    {
        return $this->algo;
    }

}
