<?php
/**
 * Created by PhpStorm.
 * User: sgueye
 * Date: 11/14/2016
 * Time: 10:54 AM
 */

namespace Barryvdh\Security;

use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;


class TokenStorage implements TokenStorageInterface
{
    private $token;
    private $tokenGenerator;

    public function __construct($tokenGenerator)
    {
        $this->tokenGenerator = $tokenGenerator;
    }

    /**
     * {@inheritdoc}
     */
    public function getToken()
    {
        if(null === $this->token) {
            $token = call_user_func($this->tokenGenerator);
            if($token) {
                $this->setToken($token);
            }
        }
        return $this->token;
    }

    /**
     * {@inheritdoc}
     */
    public function setToken(TokenInterface $token = null)
    {
        $this->token = $token;
    }
}