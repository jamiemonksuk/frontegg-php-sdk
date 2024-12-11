<?php

namespace Frontegg\GeneralAuth;

use Frontegg\Base\AuthenticatedClient;
use Frontegg\Exception\AuthenticationException;
use Frontegg\Http\RequestInterface;

class GeneralAuthClient extends AuthenticatedClient
{

    /**
     * Generate a code challenge to secure the login flow
     *
     * @param string $code_verifier
     * @return string
     */
    private function generateCodeChallenge(string $code_verifier): string
    {
        $hash = hash('sha256', $code_verifier, true);
        $base64_hash = base64_encode($hash);

        return str_replace(['+', '/', '='], ['-', '_', ''], $base64_hash);
    }


    /**
     * Generate a login URL for a user to complete a hosted login flow.
     *
     * The redirect_uri must have an origin in the 'Allowed Origins' list
     *  in the 'Keys & Domains' section of the Frontegg admin portal.
     *
     * The same code verifier must be used for this and the callback check.
     *
     * @param string $code_verifier. The code verifier to use for the login flow.
     * @param string $redirect_uri. The redirect URI to use for the login flow.
     *
     * @return string The URL that the user should be redirected to.
     * @throws AuthenticationException
     */
    public function getLoginRedirectUrl(string $code_verifier, string $redirect_uri): string
    {
        $this->validateAuthentication();

        $url = $this->getAuthenticator()->getConfig()->getVendorBaseUrl() . '/oauth/authorize';
        $code_challenge = $this->generateCodeChallenge($code_verifier);

        $params = [
            'client_id' => $this->getAuthenticator()->getConfig()->getClientId(),
            'redirect_uri' => $redirect_uri,
            'response_type' => 'code',
            'scope' => 'openid',
            'code_challenge' => $code_challenge,
        ];
        $query = http_build_query($params);

        return "{$url}?{$query}";
    }



    public function verifyCallback(string $code_verifier, string $redirect_uri, string $authorization_code)
    {
        $this->validateAuthentication();

        $url = $this->getAuthenticator()->getConfig()->getVendorBaseUrl() . '/oauth/token';

        $params = [
            'grant_type' => 'authorization_code',
            'code' => $authorization_code,
            'redirect_uri' => $redirect_uri,
            'code_verifier' => $code_verifier,
        ];

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
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

        $url = $this->getAuthenticator()->getConfig()->getVendorBaseUrl() . '/oauth/token';

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        $params = [
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
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
     * Get the URL for the Frontegg hosted portal.
     *
     * @return string
     * @throws AuthenticationException
     */
    public function getPortalRedirectUrl()
    {
        $this->validateAuthentication();

        return $this->getAuthenticator()->getConfig()->getVendorBaseUrl() . '/oauth/portal';
    }


    /**
     * Get the URL for the Frontegg hosted logout.
     *
     * @return string
     * @throws AuthenticationException
     */
    public function getLogoutRedirectUrl()
    {
        $this->validateAuthentication();

        return $this->getAuthenticator()->getConfig()->getVendorBaseUrl() . '/oauth/account/logout';
    }

}
