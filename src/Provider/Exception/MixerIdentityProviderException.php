<?php

namespace Morgann\OAuth2\Client\Mixer\Provider\Exception;

use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Psr\Http\Message\ResponseInterface;

/**
 * Class MixerIdentityProviderException
 * @package Morgann\OAuth2\Client\Mixer\Provider\Exception
 */
class MixerIdentityProviderException extends IdentityProviderException
{
    /**
     * Creates identity exception from response.
     * @param  ResponseInterface $response
     * @param  string|null $message
     * @return IdentityProviderException
     * @throws \Morgann\OAuth2\Client\Mixer\Provider\Exception\MixerIdentityProviderException
     */
    public static function fromResponse(ResponseInterface $response, $message = null)
    {
        throw new static($message, $response->getStatusCode(), (string) $response->getBody());
    }
}