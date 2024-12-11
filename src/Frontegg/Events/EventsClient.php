<?php

namespace Frontegg\Events;

use Frontegg\Base\AuthenticatedClient;
use Frontegg\Config\Config;
use Frontegg\Events\Config\TriggerOptionsInterface;
use Frontegg\Exception\EventTriggerException;
use Frontegg\Exception\FronteggSDKException;
use Frontegg\Exception\InvalidParameterException;
use Frontegg\Exception\InvalidUrlConfigException;
use Frontegg\Http\ApiRawResponse;
use Frontegg\Http\RequestInterface;
use Frontegg\Http\Response;
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

        if (
            !in_array(
                $lastResponse->getHttpResponseCode(),
                Response::getSuccessHttpStatuses()
            )
        ) {
            if (empty($lastResponse->getBody())) {
                throw new EventTriggerException($lastResponse->getBody());
            }
            $this->setErrorFromResponseData($lastResponse);

            return false;
        }

        return true;
    }

    /**
     * Sets an error data from response data.
     * Sets access token to null.
     *
     * @param ApiRawResponse $response
     *
     * @return void
     */
    protected function setErrorFromResponseData(ApiRawResponse $response): void
    {
        $errorDecoded = $this->getDecodedJsonData(
            $response->getBody()
        );

        $this->setApiError(
            $errorDecoded['error'] ?? '',
            $errorDecoded['message'] ? print_r($errorDecoded['message'], true) : '',
            $errorDecoded['statusCode'] ?? null
        );
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
