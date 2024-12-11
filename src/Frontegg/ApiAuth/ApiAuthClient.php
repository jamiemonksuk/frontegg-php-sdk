<?php

namespace Frontegg\ApiAuth;

use Frontegg\Base\AuthenticatedClient;
use Frontegg\Config\Config;
use Frontegg\Exception\AuthenticationException;
use Frontegg\Exception\FronteggSDKException;
use Frontegg\Exception\InvalidUrlConfigException;
use Frontegg\Http\RequestInterface;
use Frontegg\Json\ApiJsonTrait;

class ApiAuthClient extends AuthenticatedClient
{
    use ApiJsonTrait;


    /**
     * Create a new user access token for a client ID and secret.
     *
     * This si for end users to access your API, using tokens they can manage.
     *
     * @param string $clientId Client ID as per the API key created by the user
     * @param string $clientSecret Client secret as per the API key created by the user
     *
     * @throws FronteggSDKException
     * @throws InvalidUrlConfigException
     *
     * @return array
     */
    public function getAccessToken(string $clientId, string $clientSecret): array|null
    {
        $this->validateAuthentication();

        $url = $this->getApiAuthServiceUrl();

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        $params = [
            'clientId' => $clientId,
            'secret' => $clientSecret,
        ];

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_POST,
            json_encode($params),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        // Allow null response if not found
        return $response;
    }


    /**
     * Get a new access token from a refresh token.
     *
     * @param string $refreshToken
     * @return array
     * @throws AuthenticationException
     */
    public function refreshAccessToken(string $refreshToken): array
    {
        $this->validateAuthentication();

        $url = $this->getApiAuthServiceUrl();
        $url .= "/token/refresh";

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        $params = [
            'refreshToken' => $refreshToken,
        ];

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_POST,
            json_encode($params),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        return $response;
    }


    /**
     * Returns generic api auth service URL from config.
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    protected function getApiAuthServiceUrl(): string
    {
        return $this->authenticator->getConfig()
            ->getServiceUrl(
                Config::API_AUTHENTICATION_SERVICE
            );
    }

}
