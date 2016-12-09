<?php
declare(strict_types=1);
namespace Onion\Security\JWT;

use Onion\Security\Encryption\Interfaces;

class Manager
{
    private $defaultHeader = [];
    private $algo;

    public function __construct(Interfaces\Algorithm $algo, array $defaultHeader = [])
    {
        $this->algo = $algo;
        $this->defaultHeader['alg'] = $algo->getName();
        $this->defaultHeader['typ'] = 'JWT';
        $this->defaultHeader = array_merge($this->defaultHeader, $defaultHeader);
    }

    public function generate(array $claims, array $header = []): string
    {
        $payload = '';
        $payload .= base64_urlencode(json_encode(array_merge($this->defaultHeader, $header)));
        $payload .= '.';
        $payload .= base64_urlencode(json_encode($claims));
        $payload .= '.' . base64_urlencode($this->algo->sign($payload));

        return $payload;
    }

    public function verify(string $token): bool
    {
        list ($header, $claims, $signature)=explode('.', $token);
        if (!$this->algo->sign("$header.$claims") === $signature) {
            return false;
        }

        $claims = base64_urldecode($claims);

        if (!isset($claims['nbf'])) {
            trigger_error('JWT token does not provide "nbf" claim', PHP_USER_NOTICE);
        } elseif ($claims['nbf'] > time()) {
            throw new \LogicException(
                'JWT token provides "nbf" claim which has not been met (token used before it is supposed to)'
            );
        }

        if (!isset($claims['exp'])) {
            trigger_error('JWT token does not provide "exp" claim (might present a sec issue)', PHP_USER_WARNING);
        } elseif ($claims['exp'] >= time()) {
            return false;
        }

        if (!isset($claims['iat'])) {
            trigger_error('JWT token does not provide "iat" claim', PHP_USER_NOTICE);
        }

        if (!isset($claims['aud'])) {
            trigger_error('JWT token does not provide "aud" claim', PHP_USER_NOTICE);
        }

        if (!isset($claims['iss'])) {
            trigger_error('JWT token does not provide "iss" claim', PHP_USER_NOTICE);
        }

        return true;
    }
}
