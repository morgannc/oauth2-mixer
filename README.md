Mixer provider for league/oauth2-client
=========================================

[![pipeline status](https://gitlab.com/morgann/oauth2-mixer/badges/develop/pipeline.svg)](https://gitlab.com/morgann/oauth2-mixer/commits/develop)
[![coverage report](https://gitlab.com/morgann/oauth2-mixer/badges/develop/coverage.svg)](https://gitlab.com/morgann/oauth2-mixer/commits/develop)

This is a package to integrate mixer authentication with the [OAuth2 client library](https://github.com/thephpleague/oauth2-client) by
[The League of Extraordinary Packages](http://thephpleague.com).

Installation
------------------------------

To install, use composer:

```bash
composer require morgann/oauth2-mixer
```

Usage
------------------------------

Usage is the same as the league's OAuth client, using `\Morgann\OAuth2\Client\Mixer\Provider\Mixer` as the provider.
For example:

```php
$provider = new \Morgann\OAuth2\Client\Mixer\Provider\Mixer([
    'clientId' => "YOUR_CLIENT_ID",
    'clientSecret' => "YOUR_CLIENT_SECRET",
    'redirectUri' => "http://your-redirect-uri"
]);
```

You can also optionally add a `scopes` key to the array passed to the constructor. The available scopes are documented
on the [Mixer API Documentation](https://dev.mixer.com/reference/oauth/scopes).

> Note: The provider uses the "user:details:self" scope by default. If you pass other scopes, and want the ->getResourceOwner() method
to work, you will need to ensure the "user:details:self" scope is used.

```php
if (isset($_GET['code']) && $_GET['code']) {
    $token = $this->provider->getAccessToken("authorization_code", [
        'code' => $_GET['code']
    ]);

    // Returns an instance of Morgann\OAuth2\Client\Mixer\Entity\MixerUser
    $user = $this->provider->getResourceOwner($token);
    
    $user->getId();
    $user->getAvatar()
    $user->getBio();
    $user->getCreatedAt();
    $user->getEmail();
    $user->getExperience();
    $user->getLevel();
    $user->getName();
```

Symfony Framework Integration
------------------------------

Full documentation for adding providers is available at [KnpUOAuth2ClientBundle](https://github.com/knpuniversity/oauth2-client-bundle).

#### Step 1 - Configure provider

Add Mixer in list of providers

```yml
# config/packages/knpu_oauth2_client.yaml
knpu_oauth2_client:
  clients:
    # ...
    mixer:
      type: generic
      provider_class: Morgann\OAuth2\Client\Mixer\Provider\Mixer
      client_id: '%env(resolve:OAUTH_MIXER_ID)%'
      client_secret: '%env(resolve:OAUTH_MIXER_SECRET)%'
      redirect_route: connect_mixer_check
      redirect_params: {}
```

Add your credentials in env

```dotenv
OAUTH_MIXER_ID=XXXXXXXXXXX
OAUTH_MIXER_SECRET=XXXXXXXXXXX
```

#### Step 2 - Add the client controller

Create the Mixer authenticator controller

```php
<?php

namespace App\Controller\Authenticator;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class MixerController extends AbstractController
{
    /**
     * Connect
     * @Route("/connect/mixer", name="connect_mixer")
     * @param \KnpU\OAuth2ClientBundle\Client\ClientRegistry $clientRegistry
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function connectAction(ClientRegistry $clientRegistry)
    {
        return $clientRegistry
            ->getClient('mixer')
            ->redirect();
    }

    /**
     * Connect check
     * @Route("/connect/mixer/check", name="connect_mixer_check")
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\JsonResponse|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function connectCheckAction(Request $request)
    {
        if (!$this->getUser()) {
            return new JsonResponse(array('status' => false, 'message' => "User not found!"));
        } else {
            return $this->redirectToRoute('home');
        }
    }
}

```

#### Step 3 - Add the guard authenticator

Now create the Mixer authenticator guard :

```php
<?php

namespace App\Security\Authenticator;

use App\Entity\UserEntity;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class MixerAuthenticator extends SocialAuthenticator
{
    private $clientRegistry;
    private $em;
    private $router;
    private $encoder;

    /**
     * Constructor
     * @param \KnpU\OAuth2ClientBundle\Client\ClientRegistry $clientRegistry
     * @param \Doctrine\ORM\EntityManagerInterface $em
     * @param \Symfony\Component\Routing\RouterInterface $router
     * @param \Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface $encoder
     */
    public function __construct(ClientRegistry $clientRegistry, EntityManagerInterface $em, RouterInterface $router, UserPasswordEncoderInterface $encoder)
    {
        $this->clientRegistry = $clientRegistry;
        $this->em = $em;
        $this->router = $router;
        $this->encoder = $encoder;
    }

    /**
     * Supports
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \Symfony\Component\HttpFoundation\Request $request
     */
    public function supports(Request $request)
    {
        return $request->getPathInfo() == '/connect/mixer/check' && $request->isMethod('GET');
    }

    /**
     * Get credentials
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @return \League\OAuth2\Client\Token\AccessToken
     */
    public function getCredentials(Request $request)
    {
        return $this->fetchAccessToken($this->getMixerClient());
    }

    /**
     * Get user
     * @param array $credentials
     * @param \Symfony\Component\Security\Core\User\UserProviderInterface $userProvider
     * @return \App\Entity\UserEntity $user
     * @throws \Exception
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        $mixerUser = $this->getMixerClient()
            ->fetchUserFromToken($credentials);

        $email = $mixerUser->getEmail();

        $user = $this->em->getRepository('App:UserEntity')
            ->findOneBy(['email' => $email]);
        if (!$user) {
            $user = new UserEntity();
            $user->setEmail($mixerUser->getEmail());
            $user->setFullname($mixerUser->getName());
            $user->setPassword(
                $this->encoder->encodePassword(
                    $user,
                    base64_encode(random_bytes(10))
                )
            );
            $this->em->persist($user);
            $this->em->flush();
        }

        return $user;
    }

    /**
     * Get Mixer Client
     * @return \KnpU\OAuth2ClientBundle\Client\OAuth2Client
     */
    private function getMixerClient()
    {
        return $this->clientRegistry
            ->getClient('mixer');
    }

    /**
     * Returns a response that directs the user to authenticate
     * @param Request $request
     * @param \Symfony\Component\Security\Core\Exception\AuthenticationException $authException
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function start(Request $request, \Symfony\Component\Security\Core\Exception\AuthenticationException $authException = null)
    {
        return new RedirectResponse('/login');
    }

    /**
     * Called when authentication executed but failed
     * @param Request $request
     * @param \Symfony\Component\Security\Core\Exception\AuthenticationException $exception
     * @return \Symfony\Component\HttpFoundation\Response|null
     *
     * @todo Implement onAuthenticationFailure() method.
     */
    public function onAuthenticationFailure(Request $request, \Symfony\Component\Security\Core\Exception\AuthenticationException $exception)
    {
    }

    /**
     * Called when authentication executed and was successful
     * @param Request $request
     * @param \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token
     * @param string $providerKey
     * @return void
     *
     * @todo Implement onAuthenticationSuccess() method.
     */
    public function onAuthenticationSuccess(Request $request, \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token, $providerKey)
    {
    }
}
```

Now you can register your authenticator in security configuration file :

```yml
security:
    # ...
    firewalls:
        # ...
        main:
            # ...
            guard:
                authenticators:
                    - App\Security\Authenticator\MixerAuthenticator
```

Laravel Framework Integration
------------------------------

This package includes Laravel framework integration if you need it. Simply require it as normal in your Laravel application,
and add the Service Provider `Morgann\OAuth2\Client\Mixer\FrameworkIntegration\Laravel\MixerOAuth2ServiceProvider` to your `config/app.php`.

Next, publish the configuration with `php artisan vendor:publish`, and fill out your client
details in the `config/morgann/oauth2-mixer/config.php` file that is generated.

This will register bindings in the IoC container for the Mixer Provider, so you can simply typehint the
`\Morgann\OAuth2\Client\Mixer\Provider\Mixer` in your controller methods and it will yield a properly configured
instance.
) for details.

Testing
---------
Tests can be run with:

```bash
composer phpunit
```

Navigating to `/build/coverage/html/index.html` for html coverage logs.

Contributing
---------
Please see [CONTRIBUTING](https://gitlab.com/morgann/oauth2-mixer/blob/develop/CONTRIBUTING.md

Credits
---------
- [Morgann Collet](https://gitlab.com/morgann)

License
---------
The MIT License (MIT). Please see [License File](https://gitlab.com/morgann/oauth2-mixer/blob/develop/LICENSE) for more information.