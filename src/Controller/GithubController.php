<?php

namespace App\Controller;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;


class GithubController extends AbstractController
{
    #[Route(path: '/connect/github', name: 'github_connect')]
    public function connectAction(ClientRegistry $clientRegistry) : RedirectResponse
    {
        $client = $clientRegistry->getClient('github');
        return $client->redirect(['user:email', 'read:user']);
    }

    #[Route(path: '/connect/github/check', name: 'github_redirect_url')]
    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry)
    {

    }
}