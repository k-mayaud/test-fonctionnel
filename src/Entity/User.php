<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\ORM\Mapping\Entity;
use Doctrine\Common\Collections\ArrayCollection;
use JetBrains\PhpStorm\Pure;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @ORM\Entity
 * @ORM\Table
 */
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    const MAX_ADVICED_DAILY_CALORIES = 2500;
 
    /**
     * @ORM\Column(type="integer")
     * @ORM\Id
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    private int $id;

    /**
     * @ORM\Column
     */
    private string $username;

    /**
     * @ORM\Column
     */
    private string $fullname;

    /**
     * @ORM\Column(type="string", length=255, unique=true, nullable=true)
     */
    private string $email;

    /**
     * @ORM\Column
     */
    private string $avatarUrl;

    /**
     * @ORM\Column
     */
    private string $profileHtmlUrl;

    /**
     * @ORM\Column(type="string", length=255, nullable=true)
     */
    private $githubId;

    /**
     * @ORM\Column(name="password", type="string", length=255, options={"default" : 0000})
     */
    private $password;

    /**
     * @ORM\Column(type="array", nullable=true)
     */
    private $roles = ['ROLE_USER'];

    #[Pure]
//    public function __construct($username, $fullname, $email, $avatarUrl, $profileHtmlUrl)
//    {
//        $this->username = $username;
//        $this->fullname = $fullname;
//        $this->email = $email;
//        $this->avatarUrl = $avatarUrl;
//        $this->profileHtmlUrl = $profileHtmlUrl;
//        $this->foodRecords = new ArrayCollection();
//    }

    /**
     * @return mixed
     */
    public function getId(): mixed
    {
        return $this->id;
    }

    /**
     * @return mixed
     */
    public function getUsername(): mixed
    {
        return $this->username;
    }

    /**
     * @return mixed
     */
    public function getFullname(): mixed
    {
        return $this->fullname;
    }

    /**
     * @return mixed
     */
    public function getEmail(): mixed
    {
        return $this->email;
    }

    /**
     * @return mixed
     */
    public function getAvatarUrl(): mixed
    {
        return $this->avatarUrl;
    }

    /**
     * @return mixed
     */
    public function getProfileHtmlUrl(): mixed
    {
        return $this->profileHtmlUrl;
    }

    /**
     * @return string[]
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // guarantee every user at least has ROLE_USER
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    public function eraseCredentials()
    {
        // TODO: Implement eraseCredentials() method.
    }

    public function getUserIdentifier(): string
    {
        return '';
    }

    /**
     * @param string $username
     */
    public function setUsername(string $username): void
    {
        $this->username = $username;
    }

    /**
     * @param string $fullname
     */
    public function setFullname(string $fullname): void
    {
        $this->fullname = $fullname;
    }

    /**
     * @param string $email
     */
    public function setEmail(?string $email): void
    {
        $this->email = $email;
    }

    /**
     * @param string $avatarUrl
     */
    public function setAvatarUrl(string $avatarUrl): void
    {
        $this->avatarUrl = $avatarUrl;
    }

    /**
     * @param string $profileHtmlUrl
     */
    public function setProfileHtmlUrl(string $profileHtmlUrl): void
    {
        $this->profileHtmlUrl = $profileHtmlUrl;
    }

    public function getGithubId(): ?string
    {
        return $this->githubId;
    }

    public function setGithubId(?string $githubId): self
    {
        $this->githubId = $githubId;

        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(string $password): self
    {
        $this->password = $password;

        return $this;
    }

    public function setRoles(?array $roles)
    {
        $this->roles = $roles;
    }
}