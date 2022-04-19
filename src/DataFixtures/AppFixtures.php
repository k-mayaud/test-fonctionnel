<?php

namespace App\DataFixtures;

use Faker;
use App\Entity\User;
use Doctrine\Persistence\ObjectManager;
use Doctrine\Bundle\FixturesBundle\Fixture;

class AppFixtures extends Fixture
{
    public function load(ObjectManager $manager): void
    {
        $faker = Faker\Factory::create('fr_FR');
        for ($i = 0; $i < 2; $i++) {
            $user = new User();
            $user->setUserName($faker->userName);
            $user->setFullname($faker->lastName);
            $user->setEmail($faker->email);
            $user->setAvatarUrl($faker->url . '_avatar');
            $user->setProfileHtmlUrl($faker->url. '_profile');
            $user->setPassword('test');
            $user->setRoles(['ROLE_USER']);
            $manager->persist($user);
        }
        $manager->flush();
    }
}
