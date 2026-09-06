# ORADAD2

Criblage ORADAD — extracteur PowerShell ( aussi proche que possible de l'original mais sans utiliser un .EXE ) + décodeur HTML local, bien moins fin que la boucle standard d'analyse via EMAIL qu'elle ne peut pas remplacer mais "rapide"...

Réimplémentation en PowerShell natif de l'extraction LDAP d'ORADAD (binaire original de l'ANSSI, dont ce projet ne dépend plus), couplée à un analyseur local qui rejoue le référentiel de contrôle Active Directory du CERT-FR.

oradad.ps1  ──►  fichiers .tsv (UTF-16LE+BOM)  ──►  oradad_criblage_local.html  ──►  score + recommandations
(extracteur)      un fichier par requête LDAP        (décodeur, local, hors ligne)
Extracteur — oradad.ps1
.NET natif (System.DirectoryServices.Protocols), aucune librairie tierce, aucune compilation.
Pilote par config-oradad.xml (niveau, confidentialité, complément SYSVOL) et oradad-schema.xml (85 requêtes LDAP couvrant objets AD, schéma, réplication DFSR/FRS, PKI, DNS, Exchange).
Sortie strictement conforme à format-sortie-oradad.json : un .tsv par requête, UTF-16LE+BOM, séparateur TAB, fin de ligne CRLF, valeurs multiples jointes par ;.
Complément lecture seule (fusionné dans le même script, -SkipComplement pour le désactiver) : ACL SYSVOL, propriétés des zones DNS, reliquat FRS.
Décodeur — oradad_criblage_local.html
Page HTML autonome : aucune librairie, aucun appel réseau, traitement 100% local dans le navigateur.
Charge les .tsv produits par l'extracteur, fusionne les enregistrements par dn (server pour rootDSE).
Évalue les 156 points du référentiel CERT-FR (76 vulnérabilités, 38 avertissements, 42 informations), niveaux de sécurité 1 à 4/5.
Produit un score de maturité et le détail justifié de chaque point de contrôle.
Compatibilité extracteur → décodeur
Aspect	Extracteur	Décodeur
Encodage	UTF-16LE+BOM	détection BOM automatique
Séparateur / fin de ligne	TAB / CRLF	split CRLF puis TAB
Clé de fusion	dn (server pour rootDSE)	r.dn ?? r.server
Nommage fichier	<requête>.tsv	résolution par regex (insensible à la casse)
Valeurs multiples	jointes par ;	split sur ;
Documentation

Documentation technique complète : oradad_doc_technique.odt (LibreOffice Writer).

Sources / références
Dépôt GitHub original ANSSI-FR/ORADAD : https://github.com/ANSSI-FR/ORADAD
Référentiel de contrôle Active Directory (CERT-FR) : https://cert.ssi.gouv.fr/uploads/ad_checklist.html
Licence

Ce projet est un patch/fork du code source ANSSI-FR/ORADAD (GPL-3.0) : conformité GPL-3.0 requise.
