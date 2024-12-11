<?php

namespace Frontegg\Error;

use Frontegg\Exception\FronteggSDKException;
use Frontegg\Http\ApiRawResponse;

trait ApiErrorTrait
{
    /**
     * @var ApiError|null
     */
    protected $apiError;

    /**
     * @return ApiError|null
     */
    public function getApiError(): ?ApiError
    {
        return $this->apiError;
    }

    /**
     * @param string   $error
     * @param string   $message
     * @param int|null $statusCode
     */
    protected function setApiError(
        string $error,
        string $message,
        int $statusCode = null
    ): void {
        $this->apiError = new ApiError(
            $error,
            $message,
            $statusCode
        );
    }

    /**
     * Look at the last response and throw exceptions if needed
     *
     * Can either throw an error, or assign it to a new ApiError object
     *
     * @param ApiRawResponse $lastResponse
     * @param bool $throw Optionally throw the error on the spot
     * @return bool
     *
     * @throws FronteggSDKException
     */
    protected function validateLastResponse(ApiRawResponse $lastResponse, bool $throw = true): bool
    {
        $has_error = false;

        if (substr($lastResponse->getHttpResponseCode(), 0, 1) != '2') {
            $has_error = true;
            $this->setErrorFromResponseData($lastResponse);

            if (!$throw) {
                return $has_error;
            }

            $response = $this->getDecodedJsonData($lastResponse->getBody());

            if (!empty($response['errors'])) {
                throw new FronteggSDKException(implode(', ', $response['errors']));
            }

            if (!empty($response['message'])) {
                throw new FronteggSDKException($response['message']);
            }

            if (!empty($lastResponse->getBody())) {
                throw new FronteggSDKException($lastResponse->getBody());
            }

            throw new FronteggSDKException("Unknown error. Response code {$lastResponse->getHttpResponseCode()}");
        }

        return $has_error;
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
            ($errorDecoded['message'] ?? null) ? print_r($errorDecoded['message'], true) : '',
            $errorDecoded['statusCode'] ?? null
        );
    }
}
