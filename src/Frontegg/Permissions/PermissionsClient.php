<?php

namespace Frontegg\Permissions;

use Frontegg\Base\AuthenticatedClient;
use Frontegg\Config\Config;
use Frontegg\Exception\AuthenticationException;
use Frontegg\Exception\FronteggSDKException;
use Frontegg\Exception\InvalidUrlConfigException;
use Frontegg\Http\RequestInterface;
use Frontegg\Json\ApiJsonTrait;

class PermissionsClient extends AuthenticatedClient
{
    use ApiJsonTrait;


    /**
     * Get system-wide permissions
     *
     * @see https://developers.frontegg.com/api/identity/permissions/permissionscontrollerv1_getallpermissions
     *
     * @return array
     */
    public function getPermissions(): array|null
    {
        $this->validateAuthentication();
        $url = $this->getPermissionsServiceUrl();

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

        return $response;
    }


    /**
     * Create a new permission
     *
     * @see https://developers.frontegg.com/api/identity/permissions/permissionscontrollerv1_addpermissions
     *
     * @param string $key
     * @param string $name
     * @param string $assignment_type  Enum "NEVER", "ALWAYS", "ASSIGNABLE"
     * @param string $description
     * @param string $categoryId
     * @return array|null
     * @throws AuthenticationException
     * @throws FronteggSDKException
     */
    public function createPermission(
        string $key,
        string $name,
        string $assignment_type,
        string $description = '',
        string $categoryId = '',
    ): array|null
    {
        $this->validateAuthentication();
        $url = $this->getPermissionsServiceUrl();

        $params = [
            'key' => $key,
            'name' => $name,
            'assignment_type' => $assignment_type,
            'description' => $description,
            'categoryId' => $categoryId,
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
     * Create multiple permissions as once. Expects array of permissions in $this->createPermission format
     *
     * @param array $permissions
     * @return array|null
     * @throws AuthenticationException
     * @throws FronteggSDKException
     * @throws InvalidUrlConfigException
     */
    public function createPermissions(array $permissions): array|null
    {
        $this->validateAuthentication();
        $url = $this->getPermissionsServiceUrl();

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

        $lastResponse = $this->getHttpClient()->send(
            $url,
            RequestInterface::METHOD_POST,
            json_encode($permissions),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());

        $response = $this->getDecodedJsonData($lastResponse->getBody());

        return $response;
    }


    /**
     * Update an existing permission
     *
     * @see https://developers.frontegg.com/api/identity/permissions/permissionscontrollerv1_updatepermission
     *
     * @param string $permissionId
     * @param string $key
     * @param string $name
     * @param string $assignment_type
     * @param string $description
     * @param string $categoryId
     * @return array|null
     * @throws AuthenticationException
     * @throws FronteggSDKException
     */
    public function updatePermission(
        string $permissionId,
        string $key,
        string $name,
        string $description = '',
        string $categoryId = '',
    ): array|null
    {
        $this->validateAuthentication();
        $url = $this->getPermissionsServiceUrl() . "/{$permissionId}";

        $params = [
            'key' => $key,
            'name' => $name,
            'description' => $description,
            'categoryId' => $categoryId,
        ];

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

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
     * Delete a permission by ID
     *
     * @param string $permissionId
     * @return bool
     * @throws AuthenticationException
     * @throws FronteggSDKException
     */
    public function deletePermission(string $permissionId): bool
    {
        $this->validateAuthentication();
        $url = $this->getPermissionsServiceUrl() . "/{$permissionId}";

        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $this->getAccessTokenValue(),
        ];

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
     * Returns generic permissions service URL from config.
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    protected function getPermissionsServiceUrl(): string
    {
        return $this->authenticator->getConfig()
            ->getServiceUrl(
                Config::PERMISSIONS_SERVICE
            );
    }
}
