<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Symfony\Component\KeyManagement\Bridge\AwsKms\Tests;

use AsyncAws\Core\AbstractApi;
use AsyncAws\Core\HttpClient\AwsRetryStrategy;
use AsyncAws\Kms\KmsClient;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;
use Symfony\Component\HttpClient\RetryableHttpClient;
use Symfony\Component\KeyManagement\Bridge\AwsKms\AwsKms;
use Symfony\Component\KeyManagement\Bridge\AwsKms\AwsKmsFactory;
use Symfony\Component\KeyManagement\Dsn;
use Symfony\Component\KeyManagement\Exception\InvalidArgumentException;
use Symfony\Component\KeyManagement\Exception\UnsupportedSchemeException;

class AwsKmsFactoryTest extends TestCase
{
    public function testSupportsTheAwsKmsScheme()
    {
        $factory = new AwsKmsFactory();

        $this->assertTrue($factory->supports(Dsn::fromString('aws-kms://default?region=eu-west-1')));
        $this->assertFalse($factory->supports(Dsn::fromString('hashicorp-vault-transit://t@vault.local/v1/')));
    }

    public function testCreateBuildsAnAwsKmsAndConfiguresTheDefaultEndpoint()
    {
        $kms = (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://default?region=eu-west-1'));

        $this->assertInstanceOf(AwsKms::class, $kms);

        $config = self::getKmsClient($kms)->getConfiguration();
        $this->assertSame('eu-west-1', $config->get('region'));
        $this->assertTrue($config->isDefault('endpoint'));
    }

    public function testCreateForwardsExplicitCredentials()
    {
        $kms = (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://AKIA:SECRET@default?region=eu-west-1&session_token=ST'));

        $config = self::getKmsClient($kms)->getConfiguration();
        $this->assertSame('AKIA', $config->get('accessKeyId'));
        $this->assertSame('SECRET', $config->get('accessKeySecret'));
        $this->assertSame('ST', $config->get('sessionToken'));
    }

    public function testCustomEndpointIsBuiltFromHostAndPort()
    {
        $kms = (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://localhost:4566?region=eu-west-1'));

        $config = self::getKmsClient($kms)->getConfiguration();
        $this->assertSame('https://localhost:4566', $config->get('endpoint'));
    }

    public function testSchemeOptionAllowsHttpEndpointForLocalSandboxes()
    {
        $kms = (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://localhost:4566?region=eu-west-1&scheme=http'));

        $config = self::getKmsClient($kms)->getConfiguration();
        $this->assertSame('http://localhost:4566', $config->get('endpoint'));
    }

    public function testSchemeOptionRejectsArbitraryValues()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"scheme" option');
        (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://localhost:4566?region=eu-west-1&scheme=ftp'));
    }

    public function testSchemeOptionIsRejectedWithDefaultHost()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"default" host always uses the public AWS endpoint over HTTPS');
        (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://default?region=eu-west-1&scheme=http'));
    }

    public function testCreateRejectsADsnWithoutRegion()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('region');
        (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://default'));
    }

    public function testAccessKeyWithoutSecretKeyIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('secret key');
        (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://AKIA@default?region=eu-west-1'));
    }

    public function testSecretKeyWithoutAccessKeyIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('access key id');
        (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://:SECRET@default?region=eu-west-1'));
    }

    public function testUnknownDsnOptionIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown option "sesion_token"');
        (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://default?region=eu-west-1&sesion_token=ST'));
    }

    public function testArrayDsnOptionIsRejected()
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('"session_token" option');
        (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://default?region=eu-west-1&session_token[]=ST'));
    }

    public function testCreateRejectsADsnWithAnUnknownScheme()
    {
        $this->expectException(UnsupportedSchemeException::class);
        (new AwsKmsFactory())->create(Dsn::fromString('hashicorp-vault-transit://t@vault.local/v1/'));
    }

    public function testTheGivenHttpClientIsHandedToTheAwsClient()
    {
        $client = new MockHttpClient();

        $kms = (new AwsKmsFactory($client))->create(Dsn::fromString('aws-kms://default?region=eu-west-1'));

        $httpClient = (new \ReflectionClass(AbstractApi::class))->getProperty('httpClient');

        $this->assertSame($client, $httpClient->getValue(self::getKmsClient($kms)));
    }

    public function testTimeoutOptionsAreAppliedToTheGivenHttpClient()
    {
        $timeouts = [];
        $client = new MockHttpClient(static function (string $method, string $url, array $options) use (&$timeouts): MockResponse {
            $timeouts[] = [$options['timeout'], $options['max_duration']];

            return new MockResponse();
        });

        $kms = (new AwsKmsFactory($client))->create(Dsn::fromString('aws-kms://default?region=eu-west-1&timeout=2.5&max_duration=7'));
        self::getHttpClient($kms)->request('POST', 'https://kms.eu-west-1.amazonaws.com/');

        $this->assertSame([[2.5, 7.0]], $timeouts);
    }

    public function testTheClientBuiltByTheFactoryHasDefaultTimeoutsAndTheAwsRetryStrategy()
    {
        $kms = (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://default?region=eu-west-1'));

        $retryable = self::getHttpClient($kms);
        $this->assertInstanceOf(RetryableHttpClient::class, $retryable);
        $this->assertInstanceOf(AwsRetryStrategy::class, (new \ReflectionProperty(RetryableHttpClient::class, 'strategy'))->getValue($retryable));

        $options = self::getDefaultOptions($retryable);
        $this->assertSame(5.0, $options['timeout']);
        $this->assertSame(10.0, $options['max_duration']);
        $this->assertSame(0, $options['max_redirects']);
    }

    public function testTimeoutOptionsOverrideTheDefaultsOfTheClientBuiltByTheFactory()
    {
        $kms = (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://default?region=eu-west-1&timeout=3&max_duration=60'));

        $retryable = self::getHttpClient($kms);
        $this->assertInstanceOf(RetryableHttpClient::class, $retryable);

        $options = self::getDefaultOptions($retryable);
        $this->assertSame(3.0, $options['timeout']);
        $this->assertSame(60.0, $options['max_duration']);
        $this->assertSame(0, $options['max_redirects']);
    }

    #[DataProvider('provideInvalidTimeoutOptions')]
    public function testInvalidTimeoutOptionIsRejected(string $query, string $option)
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage(\sprintf('The "%s" option of the "aws-kms://" DSN must be positive.', $option));
        (new AwsKmsFactory())->create(Dsn::fromString('aws-kms://default?region=eu-west-1&'.$query));
    }

    public static function provideInvalidTimeoutOptions(): iterable
    {
        yield ['timeout=0', 'timeout'];
        yield ['timeout=-1', 'timeout'];
        yield ['timeout=abc', 'timeout'];
        yield ['timeout=1e999', 'timeout'];
        yield ['max_duration=0', 'max_duration'];
        yield ['max_duration=-5', 'max_duration'];
    }

    private static function getHttpClient(AwsKms $kms): object
    {
        return (new \ReflectionProperty(AbstractApi::class, 'httpClient'))->getValue(self::getKmsClient($kms));
    }

    private static function getDefaultOptions(RetryableHttpClient $retryable): array
    {
        $client = (new \ReflectionProperty(RetryableHttpClient::class, 'client'))->getValue($retryable);

        return (new \ReflectionProperty($client, 'defaultOptions'))->getValue($client);
    }

    private static function getKmsClient(AwsKms $kms): KmsClient
    {
        $clientProperty = (new \ReflectionClass(AwsKms::class))->getProperty('client');

        return $clientProperty->getValue($kms);
    }
}
