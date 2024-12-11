<?php

namespace Frontegg\Base;

use Frontegg\Authenticator\Authenticator;
use Frontegg\Exception\AuthenticationException;
use Frontegg\HttpClient\FronteggHttpClientInterface;
use Frontegg\Json\ApiJsonTrait;
use GuzzleHttp\Client;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWKSet;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

class AuthenticatedClient
{
    use ApiJsonTrait;

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

        /**
     * Returns generic api auth service URL from config.
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    protected function getJwksUrl(): string
    {
        $url = $this->authenticator->getConfig()
            ->getVendorBaseUrl();

        return "{$url}/.well-known/jwks.json";
    }

    /**
     * Ensure an access token is valid according to the JWT, and cross check keys.
     *
     * @param string $accessToken The JWT token to validate
     * @param string $tenantId The tenant ID this must be valid for, prevents token sharing
     * @param string $expectedType The expected type of token, e.g. 'tenantApiToken' or 'userToken'
     * @return bool
     * @throws AuthenticationException
     */
    public function validateAccessToken(string $accessToken, string $tenantId, string $expectedType): bool
    {
        $this->validateAuthentication();

        $serializer = new CompactSerializer();
        $jws = $serializer->unserialize($accessToken);

        $header = $jws->getSignature(0)->getProtectedHeader();
        $payload = json_decode($jws->getPayload(), true);

        if ($payload['exp'] < time()) {
            throw new AuthenticationException('Access token has expired.');
        }

        if ($payload['tenantId'] !== $tenantId) {
            throw new AuthenticationException('Access token is not valid for this account.');
        }

        if ($payload['type'] != $expectedType) {
            throw new AuthenticationException('Access token is not of a valid type.');
        }

        $kid = $header['kid'];
        $alg = strtoupper($header['alg']);
        $jwks_url = $this->getJwksUrl();

        $client = new Client();
        $response = $client->request('GET', $jwks_url, ['headers' => ['Accept' => 'application/jwk-set+json']]);

        if ($response->getStatusCode() !== 200) {
            throw new AuthenticationException('Error fetching API Key signature keys.');
        }

        $jwksData = json_decode($response->getBody(), true);
        $jwks = JWKSet::createFromKeyData($jwksData);

        $jwk = null;
        foreach ($jwks->all() as $key) {
            if ($key->has('kid') && $key->get('kid') === $kid) {
                $jwk = $key;
                break;
            }
        }

        if (!$jwk) {
            throw new AuthenticationException('Invalid API Key signature - not found.');
        }

        switch ($alg) {
            case 'HS256':
                $alg_class = new HS256();
                break;
            case 'RS256':
                $alg_class = new RS256();
                break;
            default:
            throw new AuthenticationException('Unsupported API Key algorithm.');
        }

        $algorithmManager = new AlgorithmManager([$alg_class]);
        $jwsVerifier = new JWSVerifier($algorithmManager);

        return $jwsVerifier->verifyWithKey($jws, $jwk, 0);
    }

}
