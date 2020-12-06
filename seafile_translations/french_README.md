## Introduction [![Build Status](https://secure.travis-ci.org/haiwen/seafile.svg?branch=master)](http://travis-ci.org/haiwen/seafile)

Seafile est un système de stockage libre de droit ( de type open source) avec des fonctionnalités de protection, de confidentialité et de travail en équipe.
Des collections de fichiers sont appelées des bibliothèques. 
Chaque bibliothèque peut être synchronisée indépendamment des autres.
Une bibliothèque peut également être cryptée avec un mot de passe choisi par l'utilisateur.
Seafile permet également aux utilisateurs de créer des groupes et de partager facilement des fichiers à ce groupe.

## Résumé des fonctionnalités

Seafile propose les fonctionnalités suivantes:

### Synchronisation de fichiers

1. Synchronisation sélective pour n'importe quel dossier.
2. Gèrer correctement des conflits de fichiers basés sur l'historique au lieu de l'horodatage.
3. Transférez uniquement le delta de contenu vers le serveur. Les transferts interrompus peuvent être repris.
4. Synchronisez avec deux serveurs ou plus.
5. Synchronisez avec les dossiers existants.

### Partage de fichiers et collaboration

1. Partage de dossiers entre utilisateurs ou dans des groupes.
2. Télécharger des liens avec des mot de passe de protection
3. Télécharger des liens
4. Contrôle des versions

### Client Drive

* Accédez à tous les fichiers dans le cloud via un lecteur virtuel.
* Les fichiers sont synchronisés à la demande.

### Protection de la vie privée

1. Chiffrement de bibliothèque avec un mot de passe choisi par l'utilisateur.
2. Chiffrement côté client lors de la synchronisation du bureau.

### Gestion des documents et des connaissances en ligne (Nouveau)

* Edition de Markdown en ligne de manière WYSIWYG
* Un flux de travail de révision provisoire pour les documents en ligne
* Gestion des métadonnées, comprenant
  * Étiquettes de fichier
  * Documents connexes
* Mode wiki
* Notifications en temps réel

Dépôts sources pour les composants de Seafile

Chaque composant de Seafile a son propre dépôt de code source sur Github.

* Démon client de synchronisation (ce dépôt): https://github.com/haiwen/seafile
* Interface graphique du client de synchronisation: https://github.com/haiwen/seafile-client
* Noyau du serveur: https://github.com/haiwen/seafile-server
* Interface utilisateur du serveur WEB: https://github.com/haiwen/seahub
* Application iOS: https://github.com/haiwen/seafile-iOS
* Application Android: https://github.com/haiwen/seadroid
* WebDAV: https://github.com/haiwen/seafdav

Avant la version 6.0, le code source de "Démon client de synchronisation" et "Noyau du serveur" étaient mélangés ensemble dans https://github.com/haiwen/seafile. Mais après la version 6.0, le cœur du serveur est séparé dans son propre dépôt. Pour cette raison, le dépôt du démon client de synchronisation est toujours la "page d'accueil" du projet Seafile sur Github.

### Construire et exécuter

Voir <http://manual.seafile.com/build_seafile/server.html>

Rapports de bugs et de demandes de fonctionnalités

Veuillez ne soumettre que les bugs dans les problèmes GitHub (les clients Pro doivent nous contacter par e-mail):

* Serveur et interface Web (Seahub): https://github.com/haiwen/seafile/issues
* Client de bureau: https://github.com/haiwen/seafile-client/issues
* Client Android: https://github.com/haiwen/seadroid/issues
* Client iOS: https://github.com/haiwen/seafile-iOS/issues

Des demandes de fonctionnalités peuvent être faites et les problèmes d'installation / d'utilisation peuvent être discutés sur le forum https://forum.seafile.com/.

Internationalisation (I18n)

* [Traduire Seafile Web UI](https://github.com/haiwen/seafile/wiki/Seahub-Translation)
* [Traduire le client de bureau Seafile](https://github.com/haiwen/seafile-client/#internationalization)
* [Traduire l'application Seafile pour Android](https://github.com/haiwen/seadroid#internationalization)
* [Traduire l'application Seafile pour iOS](https://github.com/haiwen/seafile-ios#internationalization-i18n)

Changer les identifiants

Voir <https://seacloud.cc/group/3/wiki/home/#Roadmap-ChangeLogs>

Pourquoi Open Source

Notre objectif principal est de créer un produit de première classe.
Nous pensons que cet objectif ne peut être atteint qu'en collaborant avec le monde entier.

Contribuant

Pour plus d'informations, lisez [Contribution](http://manual.seafile.com/contribution.html).

Licence

- Client Seafile iOS: Licence Apache v2
- Client Seafile Android: GPLv3
- Client de synchronisation de bureau (ce dépôt): GPLv2
- Noyau de Seafile Server: AGPLv3
- Seahub (interface utilisateur Web du serveur Seafile): licence Apache v2

Contact

Twitter: @seafile <https://twitter.com/seafile>

Forum: <https://forum.seafile.com>