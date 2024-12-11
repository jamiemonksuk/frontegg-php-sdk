<?php

namespace Frontegg\Base;

use Frontegg\Authenticator\Authenticator;
use Frontegg\Error\ThrowErrorTrait;
use Frontegg\Exception\AuthenticationException;
use Frontegg\HttpClient\FronteggHttpClientInterface;
use Frontegg\Json\ApiJsonTrait;

class AuthenticatedClient
{
    use ApiJsonTrait;
    use ThrowErrorTrait;

    /**
     * @var Authenticator
     */
    protected $authenticator;

    /**
     * VendorClient constructor.
     *
     * @param Authenticator $authenticator
     */
    public function __construct(Authenticator $authenticator)
    {
        $this->authenticator = $authenticator;
    }

    /**
     * @return Authenticator
     */
    public function getAuthenticator(): Authenticator
    {
        return $this->authenticator;
    }

    /**
     * Get the access token for the current session.
     *
     * Used for the 'x-access-token' header.
     *
     * @return string
     */
    public function getAccessTokenValue(): string
    {
        return $this->getAuthenticator()
            ->getAccessToken()
            ->getValue();
    }

    /**
     * Returns HTTP client.
     *
     * @return FronteggHttpClientInterface
     */
    protected function getHttpClient(): FronteggHttpClientInterface
    {
        return $this->authenticator->getClient();
    }

    /**
     * Validates access token.
     * Throws an exception on failure.
     *
     * @throws AuthenticationException
     *
     * @return void
     */
    protected function validateAuthentication(): void
    {
        $this->authenticator->validateAuthentication();
        if (!$this->authenticator->getAccessToken()) {
            throw new AuthenticationException('Authentication problem');
        }
    }


}
