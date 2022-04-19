<?php

declare(strict_types=1);

namespace DoctrineMigrations;

use Doctrine\DBAL\Schema\Schema;
use Doctrine\Migrations\AbstractMigration;

/**
 * Auto-generated Migration: Please modify to your needs!
 */
final class Version20220419000842 extends AbstractMigration
{
    public function getDescription(): string
    {
        return '';
    }

    public function up(Schema $schema): void
    {
        // this up() migration is auto-generated, please modify it to your needs
        $this->addSql('DROP INDEX UNIQ_8D93D649E7927C74');
        $this->addSql('CREATE TEMPORARY TABLE __temp__user AS SELECT id, username, fullname, email, avatar_url, profile_html_url, github_id, password, roles FROM user');
        $this->addSql('DROP TABLE user');
        $this->addSql('CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username VARCHAR(255) NOT NULL, fullname VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, avatar_url VARCHAR(255) NOT NULL, profile_html_url VARCHAR(255) NOT NULL, github_id VARCHAR(255) DEFAULT NULL, password VARCHAR(255) DEFAULT \'0\' NOT NULL, roles CLOB NOT NULL --(DC2Type:array)
        )');
        $this->addSql('INSERT INTO user (id, username, fullname, email, avatar_url, profile_html_url, github_id, password, roles) SELECT id, username, fullname, email, avatar_url, profile_html_url, github_id, password, roles FROM __temp__user');
        $this->addSql('DROP TABLE __temp__user');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_8D93D649E7927C74 ON user (email)');
    }

    public function down(Schema $schema): void
    {
        // this down() migration is auto-generated, please modify it to your needs
        $this->addSql('DROP INDEX UNIQ_8D93D649E7927C74');
        $this->addSql('CREATE TEMPORARY TABLE __temp__user AS SELECT id, username, fullname, email, avatar_url, profile_html_url, github_id, password, roles FROM user');
        $this->addSql('DROP TABLE user');
        $this->addSql('CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username VARCHAR(255) NOT NULL, fullname VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, avatar_url VARCHAR(255) NOT NULL, profile_html_url VARCHAR(255) NOT NULL, github_id VARCHAR(255) DEFAULT NULL, password VARCHAR(255) DEFAULT \'0\' NOT NULL, roles CLOB DEFAULT \'0\' NOT NULL)');
        $this->addSql('INSERT INTO user (id, username, fullname, email, avatar_url, profile_html_url, github_id, password, roles) SELECT id, username, fullname, email, avatar_url, profile_html_url, github_id, password, roles FROM __temp__user');
        $this->addSql('DROP TABLE __temp__user');
        $this->addSql('CREATE UNIQUE INDEX UNIQ_8D93D649E7927C74 ON user (email)');
    }
}
