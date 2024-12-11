<?php

namespace Frontegg\Roles;

use Frontegg\Base\AuthenticatedClient;
use Frontegg\Config\Config;
use Frontegg\Exception\AuthenticationException;
use Frontegg\Exception\FronteggSDKException;
use Frontegg\Exception\InvalidUrlConfigException;
use Frontegg\Http\RequestInterface;
use Frontegg\Json\ApiJsonTrait;

class RolesClient extends AuthenticatedClient
{
    use ApiJsonTrait;


    /**
     * Get system-wide roles
     *
     * @see https://developers.frontegg.com/api/identity/roles/permissionscontrollerv1_getallroles
     *
     * @param array $tenantId Optional tenant ID filter
     * @return array
     */
    public function getRoles(string $tenantId = ''): array|null
    {
        $this->validateAuthentication();
        $url = $this->getRolesServiceUrl();

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        if (!empty($tenantId)) {
            $headers['x-tenant-id'] = $tenantId;
        }

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_GET,
            '',
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        return $response;
    }


    /**
     * Create a new role
     *
     * @see https://developers.frontegg.com/api/identity/roles/permissionscontrollerv1_addroles
     *
     * @param string $key
     * @param string $name
     * @param int $level
     * @param string $description
     * @param bool $isDefault
     * @param bool $migrateRole
     * @param bool $firstUserRole
     * @param string $tenantId
     * @return array|null
     * @throws AuthenticationException
     * @throws FronteggSDKException
     */
    public function createRole(
        string $key,
        string $name,
        int $level,
        string $description = '',
        bool $isDefault = false,
        bool $migrateRole = false,
        bool $firstUserRole = false,
        string $tenantId = ''
    ): array|null
    {
        $this->validateAuthentication();
        $url = $this->getRolesServiceUrl();

        $params = [
            'key' => $key,
            'name' => $name,
            'level' => $level,
            'description' => $description,
            'isDefault' => $isDefault,
            'migrateRole' => $migrateRole,
            'firstUserRole' => $firstUserRole,
        ];

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        if (!empty($tenantId)) {
            $headers['x-tenant-id'] = $tenantId;
        }

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_POST,
            json_encode([$params]),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        return $response;
    }



    /**
     * Create multiple roles as once. Expects array of roles in $this->createRole format
     *
     * @param array $roles
     * @param string $tenantId
     * @return array|null
     * @throws AuthenticationException
     * @throws FronteggSDKException
     * @throws InvalidUrlConfigException
     */
    public function createRoles(array $roles, string $tenantId = ''): array|null
    {
        $this->validateAuthentication();
        $url = $this->getRolesServiceUrl();

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        if (!empty($tenantId)) {
            $headers['x-tenant-id'] = $tenantId;
        }

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_POST,
            json_encode($roles),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        return $response;
    }


    /**
     * Update an existing role
     *
     * @see https://developers.frontegg.com/api/identity/roles/permissionscontrollerv1_updaterole
     *
     * @param string $roleId
     * @param string $key
     * @param string $name
     * @param int $level
     * @param string $description
     * @param bool $isDefault
     * @param bool $migrateRole
     * @param bool $firstUserRole
     * @param string $tenantId
     * @return array|null
     * @throws AuthenticationException
     * @throws FronteggSDKException
     */
    public function updateRole(
        string $roleId,
        string $key,
        string $name,
        int $level,
        string $description = '',
        bool $isDefault = false,
        bool $migrateRole = false,
        bool $firstUserRole = false,
        string $tenantId = ''
    ): array|null
    {
        $this->validateAuthentication();
        $url = $this->getRolesServiceUrl() . "/{$roleId}";

        $params = [
            'key' => $key,
            'name' => $name,
            'level' => $level,
            'description' => $description,
            'isDefault' => $isDefault,
            'migrateRole' => $migrateRole,
            'firstUserRole' => $firstUserRole,
        ];

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        if (!empty($tenantId)) {
            $headers['x-tenant-id'] = $tenantId;
        }

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_PATCH,
            json_encode($params),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        return $response;
    }


    /**
     * Update an existing role with permissions
     *
     * @see https://developers.frontegg.com/api/identity/roles/permissionscontrollerv1_setpermissionstorole
     *
     * @param string $roleId
     * @param string $permissionIds
     * @return array|null
     * @throws AuthenticationException
     * @throws FronteggSDKException
     */
    public function assignPermissions(
        string $roleId,
        array $permissionIds
    ): array|null
    {
        $this->validateAuthentication();
        $url = $this->getRolesServiceUrl() . "/{$roleId}/permissions";

        $params = [
            'permissionIds' => $permissionIds,
        ];

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        if (!empty($tenantId)) {
            $headers['x-tenant-id'] = $tenantId;
        }

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
     * Delete a  by ID. Optional tenant filter
     *
     * @param string $roleId
     * @param string $tenantId
     * @return bool
     * @throws AuthenticationException
     * @throws FronteggSDKException
     */
    public function deleteRole(string $roleId, string $tenantId = ''): bool
    {
        $this->validateAuthentication();
        $url = $this->getRolesServiceUrl() . "/{$roleId}";

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        if (!empty($tenantId)) {
            $headers['x-tenant-id'] = $tenantId;
        }

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_DELETE,
            '',
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        return $lastResponse->getHttpResponseCode() == '204';
    }


    /**
     * Returns generic roles service URL from config.
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    protected function getRolesServiceUrl(): string
    {
        return $this->authenticator->getConfig()
            ->getServiceUrl(
                Config::ROLES_SERVICE
            );
    }
}
