<?php
namespace Morgann\OAuth2\Client\Mixer\Test\Provider;

use Morgann\OAuth2\Client\Mixer\Provider\Mixer;
use Morgann\OAuth2\Client\Mixer\Provider\Exception\MixerIdentityProviderException;
use Mockery as m;
use PHPUnit\Framework\TestCase;

class MixerTest extends TestCase
{
    protected $provider;

    protected function setUp():void
    {
        $this->provider = new Mixer([
            'clientId'     => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri'  => 'none'
        ]);
    }
    public function tearDown():void
    {
        m::close();
        parent::tearDown();
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);
        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testScopes()
    {
        $options = ['scope' => ["user:details:self"]];
        $url = $this->provider->getAuthorizationUrl($options);
        $this->assertStringContainsString(urlencode(implode(' ', $options['scope'])), $url);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        $this->assertEquals('/oauth/authorize', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];
        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);
        $this->assertEquals('/api/v1/oauth/token', $uri['path']);
    }

    public function testGetAccessToken()
    {
        $response = m::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"access_token":"mock_access_token", "scope":"repo,gist", "token_type":"bearer"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertNull($token->getExpires());
        $this->assertNull($token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testUserEntity()
    {
        $id = rand(1000, 9999);
        $name = 'user'.$id;
        $bio = uniqid();
        $avatarUrl = uniqid();
        $createdAt = uniqid();
        $email = uniqid();
        $experience = uniqid();
        $level = uniqid();

        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn('access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey=1234');
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);
        $postResponse->shouldReceive('getStatusCode')->andReturn(200);

        $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getBody')->andReturn($this->getMockEntity($id, $name, $bio, $avatarUrl, $createdAt, $email, $experience, $level));
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $userResponse->shouldReceive('getStatusCode')->andReturn(200);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(2)->andReturn($postResponse, $userResponse);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals($id, $user->getId());
        $this->assertEquals($name, $user->getName());
        $this->assertEquals($bio, $user->getBio());
        $this->assertEquals($avatarUrl, $user->getAvatar());
        $this->assertEquals($createdAt, $user->getCreatedAt());
        $this->assertEquals($email, $user->getEmail());
        $this->assertEquals($experience, $user->getExperience());
        $this->assertEquals($level, $user->getLevel());

        $toArray = $user->toArray();
        $this->assertFalse(empty($toArray));
        $this->assertTrue(is_array($toArray));
        $this->assertEquals($name, $toArray['username']);
        $this->assertEquals($bio, $toArray['bio']);
        $this->assertEquals($avatarUrl, $toArray['avatarUrl']);
        $this->assertEquals($createdAt, $toArray['createdAt']);
        $this->assertEquals($email, $toArray['email']);
        $this->assertEquals($experience, $toArray['experience']);
        $this->assertEquals($level, $toArray['level']);
    }

    public function testCheckResponseThrowsIdentityProviderException()
    {
        $response = m::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"ok": false, "error": "not_authed"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $response->shouldReceive('getStatusCode')->andReturn(401);

        $this->expectException(MixerIdentityProviderException::class);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->once()->andReturn($response);

        $this->provider->setHttpClient($client);
        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

    protected function getMockEntity($id, $name, $bio, $avatarUrl, $createdAt, $email, $experience, $level)
    {
        return '{
            "id": "'.$id.'",
            "avatarUrl": "'.$avatarUrl.'",
            "bio": "'.$bio.'",
            "createdAt": "'.$createdAt.'",
            "email": "'.$email.'",
            "experience": "'.$experience.'",
            "level": "'.$level.'",
            "username": "'.$name.'"
        }';
    }
}
