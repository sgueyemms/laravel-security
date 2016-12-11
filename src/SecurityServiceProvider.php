<?php namespace Barryvdh\Security;

use Illuminate\Auth\Events;
use Illuminate\Support\ServiceProvider;

use Barryvdh\Security\Authentication\AuthenticationManager;
use Barryvdh\Security\Authentication\Token\LaravelToken;

use Symfony\Component\Security\Core\Authorization\AuthorizationCheckerInterface;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage as SfTokenStorage;
use Symfony\Component\Security\Core\Authorization\AuthorizationChecker;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\Role\RoleHierarchy;


class SecurityServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = false;

    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/security.php' => config_path('security.php'),
        ], 'config');
    }

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register()
	{
        $this->mergeConfigFrom(
            __DIR__.'/../config/security.php', 'security'
        );

        $app = $this->app;

        $app['security.role_hierarchy'] = $app['config']->get('security.role_hierarchy', array());
        $app['security.strategy'] = $app['config']->get('security.strategy', 'affirmative');

        $app['security'] = $app->share(function ($app) {
                // Deprecated. Use security.authorization_checker instead.
                $security = new SecurityContext($app['security.authentication_manager'], $app['security.access_manager']);
                $security->setToken(new LaravelToken($app['auth']->user()));
                return $security;
            });

        $app['security.token_storage'] = $app->share(function($app) {
            /*
             * Issues with the user in the token being empty and Laravel never firing the
             * Events\Authenticate.
             * So I replaced the storage with one that takes a token generator that lets it delay the
             * token creation until it is needed.
             * If for some reason the token is requested too early we might run into the same issue.
             * This is not a satisfying fix because this kind of "race condition" should never happen
             */
            $tokenStorage = new TokenStorage(
                function () use ($app) { return new LaravelToken($app['auth']->user()); }
            );
            return $tokenStorage;
        });

        $app['security.authorization_checker'] = $app->share(function ($app) {
            return new AuthorizationChecker(
                $app['security.token_storage'],
                $app['security.authentication_manager'],
                $app['security.access_manager']
            );
        });
        $app->alias('security.authorization_checker', AuthorizationCheckerInterface::class);

        $app['security.authentication_manager'] = $app->share(function ($app) {
            return new AuthenticationManager();
        });

        $app['security.access_manager'] = $app->share(function ($app) {
            return new AccessDecisionManager($app['security.voters'], $app['security.strategy']);
        });

        $app->bind('Symfony\Component\Security\Core\Role\RoleHierarchyInterface', function($app) {
            return new RoleHierarchy($app['security.role_hierarchy']);
        });

        $app['security.voters'] = $app->share(function ($app) {
            return array_map(function($voter) use ($app) {
                return $app->make($voter);
            }, $app['config']->get('security.voters'));
        });

        //Listener for Login event
        $app['events']->listen(Events\Login::class, function(Events\Login $event) use($app){
            $app['security.token_storage']->setToken(new LaravelToken($event->user));
        });
        //Listener for authenticated events
        $app['events']->listen(Events\Authenticated::class, function(Events\Authenticated $event) use($app){
            //pyk_die($event->user."");
        });
        //Listener for logout events
        $app['events']->listen(Events\Logout::class, function(Events\Logout $event) use($app){
            $app['security.token_storage']->setToken(new LaravelToken(null));
        });
	}


	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides()
	{
		return array(
		    'security',
            'security.role_hierarchy' ,
            'security.authentication_manager',
            'security.access_manager',
            'security.voters',
            'security.authorization_checker'
        );
	}

}
