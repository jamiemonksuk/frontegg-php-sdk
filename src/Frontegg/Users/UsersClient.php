<?php

namespace Frontegg\Users;

use Frontegg\Base\AuthenticatedClient;
use Frontegg\Config\Config;
use Frontegg\Exception\AuthenticationException;
use Frontegg\Exception\FronteggSDKException;
use Frontegg\Exception\InvalidUrlConfigException;
use Frontegg\Exception\UserNotFoundException;
use Frontegg\Http\ApiRawResponse;
use Frontegg\Http\RequestInterface;
use Frontegg\Http\Response;
use Frontegg\Json\ApiJsonTrait;

class UsersClient extends AuthenticatedClient
{
    use ApiJsonTrait;


    /** @inheritdoc */
    protected function validateLastResponse(ApiRawResponse $lastResponse, bool $throw = true): bool
    {
        if (
            Response::HTTP_STATUS_OK
            !== $lastResponse->getHttpResponseCode()
        ) {
            $response = $this->getDecodedJsonData($lastResponse->getBody());
            $this->setErrorFromResponseData($lastResponse);

            if (!$throw) {
                return false;
            }

            if (!empty($response['errors'])) {
                if (strpos($response['errors'][0], 'User not found') !== false) {
                    throw new UserNotFoundException($response['errors'][0]);
                }
            }

            return parent::validateLastResponse($lastResponse, $throw);
        }

        return true;
    }


    /**
     * Looks up a user by user ID and tenant ID
     *
     * @param string $userId
     * @param string $tenantId
     *
     * @throws UserNotFoundException
     * @throws FronteggSDKException
     * @throws InvalidUrlConfigException
     *
     * @return array
     */
    public function getUser(string $userId, string $tenantId): array|null
    {
        $this->validateAuthentication();

        $url_base = $this->getUserServiceUrl();
        $url = "{$url_base}/{$userId}";

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
            'frontegg-tenant-id' => $tenantId,
        ];

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_GET,
            '',
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        // Allow null response if not found
        return $response;
    }


    /**
     * Looks up a user by email address
     *
     * @param string $email
     *
     * @throws UserNotFoundException
     * @throws FronteggSDKException
     * @throws InvalidUrlConfigException
     *
     * @return array
     */
    public function getUserByEmail(string $email): array|null
    {
        $this->validateAuthentication();

        $url_base = $this->getUserServiceUrl();

        $params = [
            'email' => $email,
        ];
        $query = http_build_query($params);
        $url = "{$url_base}/email?{$query}";

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_GET,
            '',
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        // Allow null response if not found
        return $response;
    }


    /**
     * Update a user's email address
     *
     * @param string $userId The frontegg user ID we are updating
     * @param string $email The new email address
     *
     * @throws UserNotFoundException
     * @throws FronteggSDKException
     * @throws InvalidUrlConfigException
     *
     * @return array
     */
    public function updateUserEmail(string $userId, string $email): array|null
    {
        $this->validateAuthentication();

        $url_base = $this->getUserServiceUrl();
        $url = "{$url_base}/{$userId}/email";

        $params = [
            'email' => $email,
        ];

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_PUT,
            json_encode($params),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        return $response;
    }


    /**
     * Update global user data. Will not update null values.
     *
     * @param string $userId The frontegg user ID we are updating
     * @param null|string $phoneNumber
     * @param null|string $profilePictureUrl
     * @param null|array $metadata
     * @param null|array $vendorMetadata
     * @param null|bool $mfaBypass
     * @param null|string $name
     * @return array
     *
     * @throws AuthenticationException
     * @throws InvalidUrlConfigException
     * @throws FronteggSDKException
     * @throws UserNotFoundException
     */
    public function updateUserGlobally(
        string $userId,
        ?string $phoneNumber = null,
        ?string $profilePictureUrl = null, // Not in docs, but must be a FE URL?
        ?array $metadata = null,
        ?array $vendorMetadata = null,
        ?bool $mfaBypass = null,
        ?string $name = null,
    ): array {
        $this->validateAuthentication();

        // Build list of parameters, non-null only
        $params = [];
        if ($phoneNumber !== null) {
            $params['phoneNumber'] = $phoneNumber;
        }
        if ($profilePictureUrl !== null) {
            $params['profilePictureUrl'] = $profilePictureUrl;
        }
        if ($metadata !== null) {
            $params['metadata'] = json_encode($metadata);
        }
        if ($vendorMetadata !== null) {
            $params['vendorMetadata'] = json_encode($vendorMetadata);
        }
        if ($mfaBypass !== null) {
            $params['mfaBypass'] = $mfaBypass;
        }
        if ($name !== null) {
            $params['name'] = $name;
        }

        $url_base = $this->getUserServiceUrl();
        $url = "{$url_base}/{$userId}";

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_PUT,
            json_encode($params),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        return $response;
    }


    /**
     * Returns generic users service URL from config.
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    protected function getUserServiceUrl(): string
    {
        return $this->authenticator->getConfig()
            ->getServiceUrl(
                Config::USERS_SERVICE
            );
    }
}
