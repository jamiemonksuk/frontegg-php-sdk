<?php

namespace Frontegg\Events;

use Frontegg\Base\AuthenticatedClient;
use Frontegg\Config\Config;
use Frontegg\Events\Config\TriggerOptionsInterface;
use Frontegg\Exception\EventTriggerException;
use Frontegg\Exception\FronteggSDKException;
use Frontegg\Exception\InvalidParameterException;
use Frontegg\Exception\InvalidUrlConfigException;
use Frontegg\Http\RequestInterface;
use Frontegg\Json\ApiJsonTrait;

class EventsClient extends AuthenticatedClient
{
    use ApiJsonTrait;


    /**
     * Trigger the event specified by trigger options.
     * Returns true on success.
     * Returns true on failure and $apiError property will contain an error.
     *
     * @param TriggerOptionsInterface $triggerOptions
     *
     * @throws EventTriggerException
     * @throws FronteggSDKException
     * @throws InvalidParameterException
     * @throws \Frontegg\Exception\InvalidUrlConfigException
     *
     * @return bool
     */
    public function trigger(TriggerOptionsInterface $triggerOptions): bool
    {
        if (!$triggerOptions->getChannels()->isConfigured()) {
            throw new InvalidParameterException(
                'At least one channel should be configured'
            );
        }

        $this->validateAuthentication();

        $accessTokenValue = $this->authenticator
            ->getAccessToken()
            ->getValue();
        $headers = [
            'Content-Type' => 'application/json',
            'x-access-token' => $accessTokenValue,
            'frontegg-tenant-id' => $triggerOptions->getTenantId(),
        ];

        $lastResponse = $this->getHttpClient()->send(
            $this->getEventsServiceUrl(),
            RequestInterface::METHOD_POST,
            json_encode([
                'eventKey' => $triggerOptions->getEventKey(),
                'properties' => $triggerOptions->getDefaultProperties()->toArray(),
                'channels' => $triggerOptions->getChannels()->toArray(),
            ]),
            $headers,
            RequestInterface::HTTP_REQUEST_TIMEOUT
        );

        return $this->validateLastResponse($lastResponse, $this->authenticator->getConfig()->isThrowOnError());
    }

    /**
     * Returns Events service URL from config.
     *
     * @throws InvalidUrlConfigException
     *
     * @return string
     */
    protected function getEventsServiceUrl(): string
    {
        return $this->authenticator->getConfig()
            ->getServiceUrl(
                Config::EVENTS_SERVICE
            );
    }

}
