# Analyseur de protocoles réseau 'offline'.


## 1 Présentation du projet

L’objectif de ce projet est de programmer un analyseur de protocoles réseau ’offline’. Il prend
en entrée un ou des fichiers traces contenant les octets capturés préalablement sur un réseau
Ethernet.
La liste des protocoles que notre analyseur est capable de comprendre sont les suivant :
- Couche 2 : Ethernet
- Couche 3 : IP
- Couche 4 : UDP
- Couche 7 : DNS et DHCP
Dans le cas de DNS, notre analyseur décode :
- les 6 champs d’entete
- les sections questions, réponses, autorités et additionnelles.


## 2 Code source

### 2.1 file main.py

Le fichier ’main.py’ est le fichier d’entrée de notre programme.
C’est le fichier d’entré de notre projet (l’exécutable). La syntax de démaragge du programme
est simple : `python3 main.py [-help] [-printout=x] file1 [filen]`
- -help : Pour afficher le mode d’emploi du programme ;
- -printout=x : Spécificie, en fonction de la valueur de x, si afficher le résultat de l’analyse
sur le terminal et/ou l’écrire dans un fichier
- x = 0 (defaul) : écrire le résultat uniquement sur le terminal ;
- x = 1 : écrire le résultat uniquement dans un fichier (le fichier en question aura le
nom res_analyse_{nom du fichier analyser}) ;
- x = 2 : écrire le résultat sur le terminal et dans un fichier.
- file1 \[filen\] : la liste des fichiers contenant les trames à analyser.

### 2.2 file packets.py

le fichier ’packets.py’ est diviser principalement en 3 grandes parties :
- lecture d’un fichier contenant une trame Ethernet et extraction des octets
- Analyse des octets et extraction des informations
- Affichage/écriture des informations extraites de la trame

#### 2.2.1 Lecture du fichier contenant la trame Ethernet

Cette opération se fait au travers de la fonction read_packets_file(name_file : str) -> list.
Il prend comme paramètre le nom du fichier contenant la trame à analyser, lit le fichier
ligne par ligne tout enn fesant un control sur l’offset. (Pour un exemple de trame, se réferer
aux fichiers ’dhcp_discover.txt’, ’dhcp_offer.txt’, ’dhcp_request.txt’, ’dhcp_ack’, ’dns1.txt’,
’dns2.txt’). Si l’offset d’une ligne est valide, alors les octets écrit sur cette ligne sont lu mais au
cas contraire, ils sont ignorés et l’on passe à la ligne suivante.
A la fin de l’exécution de la fonction, elle retourne les octets lu dans le fichier dans une liste.

#### 2.2.2 Analyse des octets et extraction des informations

Pour se faire, on a définit une fonction pour chaque protocole se trouvant sur différentw
couche.
Sur la couche 2, on analyse un seul protocole : le protocole Ethernet II (via la fonction
analyse_frame_ethernet2(frame: list) -> dict prenant en entrée une liste contenant des
octets précedement lu dans le fichier trame) qui extrait l’adresse mac destination et source, ainsi
que le protole de la couche supérieur. Après avoir connu le protocole suivant, nous passons à la
couche supérieur.
Sur la couche 3, nous analysons uniquement le protocole IPv4, via la fonction analyse_packet_ipv4(packet:
list) -> dict. Elle analyse chaque octets et y extrait les informations pour chaque champ
d’une trame IPv4. Avoir extrait toutes les informations liés au protocole IPv4, nous passons à
la couche supérieur guidé par le champ protocole.
Sur la couche 4, nous nous interessons au protocole UDP (via la fonction analyse_segment_udp(segment:
list) -> dict). En fonction de la valeur des ports source et destination, nous passons à la
couche suivante, si le segment non contient pas uniquement des données brutes.
Sur la couche 7, en fonction des valeurs des port dans le segment UDP, le protocole suivant
peut-etre DNS (examiné via la fonction analyse_datagram_dns(datagram: list) -> dict)
ou DHCP (examiné via la fonction analyse_datagram_dhcp(datagram: list) -> dict).
Pour chacune de ces fonctions, elle retourne un dictionnaire contenant une association clé
(nom du champ) -> valeur (la valeur du champ).


## 3 Fichier contenat les packets

Important : Pour les fichiers contenant les packets, il a été choisit que 2 trames doivent
etre séparé par au minimum une ligne blanche (ligne vide).


## 4 file dhcp.txt dns.txt test_dns.sh test_dhcp.txt

### 4.1 dhcp.txt et test_dhcp.sh

Le fichier dhcp.txt contient un exemple de trame dhcp utile pour faire un test. Le fichier
test_dhcp.sh contient un code minimal pour tester le fonctionnement de notre programme.

### 4.2 dns.txt et test_dns.sh

Le fichier dns.txt contient un exemple de trame dns utile pour faire un test. Le fichier
test_dns.sh contient un code minimal pour tester le fonctionnement de notre programme.

