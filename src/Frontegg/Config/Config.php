<?php

namespace Frontegg\Config;

use Frontegg\Exception\InvalidUrlConfigException;

/**
 * Class Config
 *
 * @package Frontegg
 */
class Config
{
    public const PROXY_URL = '/frontegg';

    public const ACCOUNT_ROLES_SERVICE = 'account-roles';
    public const AUTHENTICATION_SERVICE = 'authentication';
    public const AUDITS_SERVICE = 'audits';
    public const EVENTS_SERVICE = 'events';
    public const PERMISSIONS_SERVICE = 'permissions';

    public const ACCOUNT_ROLES_SERVICE_DEFAULT_URL = '/identity/resources/roles/v2';
    public const AUTHENTICATION_SERVICE_DEFAULT_URL = '/auth/vendor';
    public const AUDITS_SERVICE_DEFAULT_URL = '/audits';
    public const EVENTS_SERVICE_DEFAULT_URL = '/event/resources/triggers/v2';
    public const PERMISSIONS_SERVICE_URL = '/identity/resources/permissions/v1';

    /**
     * List of allowed API service URLs and its' default values.
     *
     * @var string[]
     */
    protected static $API_URL_KEYS = [
        self::ACCOUNT_ROLES_SERVICE => self::ACCOUNT_ROLES_SERVICE_DEFAULT_URL,
        self::AUTHENTICATION_SERVICE => self::AUTHENTICATION_SERVICE_DEFAULT_URL,
        self::AUDITS_SERVICE => self::AUDITS_SERVICE_DEFAULT_URL,
        self::EVENTS_SERVICE => self::EVENTS_SERVICE_DEFAULT_URL,
        self::PERMISSIONS_SERVICE => self::PERMISSIONS_SERVICE_URL,
    ];

    /**
     * Client ID.
     *
     * @var string
     */
    protected $clientId;

    /**
     * API secret key.
     *
     * @var string
     */
    protected $clientSecret;

    /**
     * Frontegg API base URL.
     *
     * @var string
     */
    protected $baseUrl;

    /**
     * Frontegg API base URL for authentication.
     * In hybrid mode, the base API url and authentication url may be different
     *
     * @var string
     */
    protected $authenticationBaseUrl;

    /**
     * Custom vendor region, used when determining endpoints.
     *
     * @var string
     */
    protected $vendorBaseUrl;

    /**
     * Frontegg API endpoints relative URLs.
     *
     * @var array
     */
    protected $urls;

    /**
     * @var callable
     */
    protected $contextResolver;

    /**
     * @var bool
     */
    protected $disableCors;

    /**
     * @var bool
     */
    protected $throwOnError;

    /**
     * Config constructor.
     *
     * @param string $clientId
     * @param string $clientSecret
     * @param string $baseUrl
     * @param array $urls
     * @param bool $disableCors
     * @param callable $contextResolver
     * @param string $authenticationBaseUrl
     */
    public function __construct(
        string $clientId,
        string $clientSecret,
        string $baseUrl,
        array $urls,
        bool $disableCors,
        bool $throwOnError,
        callable $contextResolver,
        string $authenticationBaseUrl,
        string $vendorBaseUrl
    ) {
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->baseUrl = trim($baseUrl, '/');
        $this->setApiUrls($urls);
        $this->contextResolver = $contextResolver;
        $this->disableCors = $disableCors;
        $this->throwOnError = $throwOnError;
        $this->authenticationBaseUrl = trim($authenticationBaseUrl, '/');
        $this->vendorBaseUrl = trim($vendorBaseUrl, '/');
    }

    /**
     * @return callable
     */
    public function getContextResolver(): callable
    {
        return $this->contextResolver;
    }

    /**
     * @return bool
     */
    public function isDisableCors(): bool
    {
        return $this->disableCors;
    }

    /**
     * @return bool
     */
    public function isThrowOnError(): bool
    {
        return $this->throwOnError;
    }

    /**
     * @return string
     */
    public function getClientId(): string
    {
        return $this->clientId;
    }

    /**
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->clientSecret;
    }

    /**
     * @return string
     */
    public function getBaseUrl(): string
    {
        return $this->baseUrl;
    }

    /**
     * @return string
     */
    public function getAuthenticationBaseUrl(): string
    {
        return $this->authenticationBaseUrl;
    }

    /**
     * @return string
     */
    public function getVendorBaseUrl(): string
    {
        return $this->vendorBaseUrl;
    }

    /**
     * Returns API URL by service name.
     *
     * @param string $urlKey
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    public function getServiceUrl(string $urlKey): string
    {
        $this->validateUrlKey($urlKey);

        if (isset($this->urls[$urlKey])) {
            return $this->baseUrl . $this->urls[$urlKey];
        }

        return $this->baseUrl . static::$API_URL_KEYS[$urlKey];
    }

    /**
     * Returns authentication URL by service name.
     *
     * @param string $urlKey
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    public function getAuthenticationUrl(string $urlKey): string
    {
        $this->validateUrlKey($urlKey);

        if (isset($this->urls[$urlKey])) {
            return $this->authenticationBaseUrl . $this->urls[$urlKey];
        }

        return $this->authenticationBaseUrl . static::$API_URL_KEYS[$urlKey];
    }

    /**
     * Returns URL of the Frontegg proxy.
     *
     * @return string
     */
    public function getProxyUrl(): string
    {
        return $this->baseUrl;
    }

    /**
     * Sets up only allowed API URLs.
     *
     * @param array $urls
     *
     * @return void
     */
    protected function setApiUrls(array $urls = []): void
    {
        $this->urls = [];

        foreach ($urls as $key => $url) {
            if (!isset(static::$API_URL_KEYS[$key])) {
                continue;
            }

            $this->urls[$key] = $url;
        }
    }

    private function validateUrlKey(string $urlKey): void
    {
        if (!isset(static::$API_URL_KEYS[$urlKey])) {
            throw new InvalidUrlConfigException(
                sprintf('URL "%s" is not a part of allowed API', $urlKey)
            );
        }
    }
}
