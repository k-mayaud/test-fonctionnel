- Avoir installé php 8 avec ses dépendances
- Avoir un Compte Github
- Avoir composer, nodeJS et Yarn d'installé
- Lancer un composer install après avoir récupéré le projet ```composer install```
- Installer driver sqlite3 ubuntu ```sudo apt install php8.0-sqlite3 ```
- Installer la base de données 
  - ```php bin/console doctrine:database:create --env=test```
  - ```php bin/console doctrine:schema:create --env=test```
  - ```php bin/console doctrine:migrations:migrate --env=test```
- ```yarn install``` Pour générer les assets css et js via encore
- ```yarn dev``` Pour regénérer les assets automatiquement
- ```symfony server:start```

  __Ne pas oublier de changer dans le fichier ```tests/Controller/DiaryControllerTest.php:21``` l'adresse mail en mettant celle qui est dans ce [lien](https://github.com/settings/emails),
  qui est celle utilisée sur Github__

- Décommentez les lignes 22 et 23 en retirant le `#` dans le ```.env``` les valeurs suivantes que vous récupérez depuis [Github](https://github.com/settings/developers)
- #GITHUB_ID=
- #GITHUB_SECRET=

---
Installation d'une application dans github:
1. Se rendre sur [Github](https://github.com/settings/developers) en cliquant sur le lien
2. Cliquer sur le bouton New OAuth App
3. Remplir le formulaire
   - Application name: food-diary
   - Homepage URL: http://127.0.0.1:8000/
   - Application description: Laisser vide ou y indiquer ce qui vous plaira ;)
   - Authorization callback URL: http://127.0.0.1:8000/auth
4. Clic sur le bouton Register application
5. Nous sommes redirigés vers la page de cette application dans gitHub ou nous pouvons récupérer
les credentials **GITHUB_ID** (qui correspond au Client ID) et le **GITHUB_SECRET** (qui correspond au Client secrets)
qu'il faudra générer en cliquant sur le bouton **Generate a new client secret**
6. Vous copiez ces valeurs dans le .env comme ceci (ces valeurs sont des exemples, copiez les vôtres ;)
   - GITHUB_ID=b6adf978b8aaa4804b47
   - GITHUB_SECRET=dcdcc25c1220c661d0fc8c901d0a569050b14858
7. Avec tout cela vous 
