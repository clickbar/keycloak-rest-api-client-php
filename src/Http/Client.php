<?php

declare(strict_types=1);

namespace Fschmtt\Keycloak\Http;

use DateTime;
use Fschmtt\Keycloak\Keycloak;
use Fschmtt\Keycloak\OAuth\TokenStorageInterface;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\ClientException;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token;
use Psr\Http\Message\ResponseInterface;

/**
 * @internal
 */
class Client
{
    public function __construct(
        private readonly Keycloak $keycloak,
        private readonly ClientInterface $httpClient,
        private readonly TokenStorageInterface $tokenStorage,
    ) {
    }

    /**
     * @param array<string, mixed> $options
     */
    public function request(string $method, string $path = '', array $options = []): ResponseInterface
    {
        if (!$this->isAuthorized()) {
            $this->authorize();
        }

        $defaultOptions = [
            'base_uri' => $this->keycloak->getBaseUrl(),
            'headers' => [
                'Authorization' => 'Bearer ' . $this->tokenStorage->retrieveAccessToken()->toString(),
            ],
        ];

        $options = array_merge_recursive($options, $defaultOptions);

        return $this->httpClient->request(
            $method,
            $this->keycloak->getBaseUrl() . $path,
            $options
        );
    }

    public function isAuthorized(): bool
    {
        return $this->tokenStorage->retrieveAccessToken()?->isExpired(new DateTime()) === false;
    }

    private function authorize(): void
    {
        $tokens = $this->fetchTokens();
        $parser = (new Token\Parser(new JoseEncoder()));

        $this->tokenStorage->storeAccessToken($parser->parse($tokens['access_token']));
        if ($tokens['refresh_token'] !== null) {
            $this->tokenStorage->storeRefreshToken($parser->parse($tokens['refresh_token']));
        }
    }

    /**
     * @return array{access_token: non-empty-string, refresh_token: non-empty-string}
     */
    private function fetchTokens(): array
    {
        $refreshToken = $this->tokenStorage->retrieveRefreshToken();
        $response = null;

        if ($refreshToken) {
            // try refreshing the token
            try {
                $response = $this->httpClient->request(
                    'POST',
                    $this->keycloak->getBaseUrl() . '/realms/master/protocol/openid-connect/token',
                    [
                        'form_params' => [
                            'refresh_token' => $this->tokenStorage->retrieveRefreshToken()?->toString(),
                            'client_id' => 'admin-cli',
                            'grant_type' => 'refresh_token',
                        ],
                    ],
                );
            } catch (ClientException $e) {

            }
        }

        if ($response === null) {
            $response = $this->httpClient->request(
                'POST',
                $this->keycloak->getBaseUrl() . '/realms/master/protocol/openid-connect/token',
                [
                    'form_params' => [
                        'client_secret' => $this->keycloak->getClientSecret(),
                        'client_id' => 'admin-cli',
                        'grant_type' => 'client_credentials',
                    ],
                ]
            );
        }

        $tokens = json_decode(
            $response->getBody()->getContents(),
            true,
            flags: JSON_THROW_ON_ERROR,
        );

        return [
            'access_token' => $tokens['access_token'],
            'refresh_token' => $tokens['refresh_token'] ?? null,
        ];
    }
}
