<?php

namespace Frontegg\AccountRoles;

use Frontegg\Base\AuthenticatedClient;
use Frontegg\Config\Config;
use Frontegg\Exception\InvalidUrlConfigException;
use Frontegg\Http\RequestInterface;
use Frontegg\Json\ApiJsonTrait;

class AccountRolesClient extends AuthenticatedClient
{
    use ApiJsonTrait;


    /**
     * Get account specific roles based on an optional set of filters
     *
     * @see https://developers.frontegg.com/api/identity/account-roles/permissionscontrollerv2_getallroles
     *
     * @param array $search_params
     * @return array
     */
    public function getRoles(array $search_params = ['_sortBy' => 'key']): array|null
    {
        $this->validateAuthentication();

        $url = $this->getAccountRolesServiceUrl();

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        $query = http_build_query($search_params);
        $url = "{$url}?{$query}";

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
     * Returns generic account roles service URL from config.
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    protected function getAccountRolesServiceUrl(): string
    {
        return $this->authenticator->getConfig()
            ->getServiceUrl(
                Config::ACCOUNT_ROLES_SERVICE
            );
    }
}
