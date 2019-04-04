<?php
namespace App\Services;

/**
 * Description of mpsAuthProvider
 *
 * @author Michael Cooper <mike.cooper@intechnologywifi.com>
 */

use Illuminate\Contracts\Auth\UserProvider as UserProviderInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use App\Services\Facades\HttpClient;
use App\Exceptions\ApiException;
use Illuminate\Http\Request;
use Carbon\Carbon;
use App\User;


class ApiAuthProvider  implements UserProviderInterface
{
    protected $request;
    
    public function __construct(Request $request)
    {
        $this->request = $request;
    }
    
    /**
     * Get and return a user by their access_token
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        if ($this->request->session()->has('user')) {
            return new User($this->request->session()->get('user'));
        }
    }

    /**
     * @param  mixed   $identifier
     * @param  string  $token
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        // Get and return a user by their unique identifier and "remember me" token
    }

    /**
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        // Save the given "remember me" token for the given user
    }

    /**
     * Retrieve a user by the given credentials.
     * @param  array  $credentials
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        $http = new \GuzzleHttp\Client;
        
        try {
            $res = $http->post(env('API_URL').'/oauth/token', [
                'form_params' => [
                    'grant_type' => 'password',
                    'client_id' => env('OAUTH_CLIENT_ID'),
                    'client_secret' => env('OAUTH_CLIENT_SECRET'),
                    'username' => $credentials['email'],
                    'password' =>$credentials['password'],
                    'scope' => '*',
                ],
            ]);
        } catch (\GuzzleHttp\Exception\RequestException $e) {
            return new User();
        }
        
        $token = $res->getBody();
        
        $headers = [
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer '.json_decode($token)->access_token,
            ];
        
        try {
            $res = $http->get(env('API_URL').'/api/user', [
                'headers' => [
                    'Accept' => 'application/json',
                    'Authorization' => 'Bearer '.json_decode($token)->access_token,
                ],
            ]);
        } catch (\GuzzleHttp\Exception\RequestException $e) {
            return new User();
        }
        
        $body = $res->getBody();
        $user = new User(json_decode($body, true));
        $user->access_token = json_decode($token)->access_token;
        Auth::getSession()->put('user', $user->toArray());
        
        return $user;
    }

    /**
     * Validate a user against the given credentials.
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        if ($user->getAttribute('access_token')) {
            return true;
        }
        
        return false;
    }

}
