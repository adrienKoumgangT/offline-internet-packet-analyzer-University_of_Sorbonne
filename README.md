# Analyseur de protocoles réseau 'offline'.


## 1 Présentation du projet

L’objectif de ce projet est de programmer un analyseur de protocoles réseau ’offline’. Il prend
en entrée un ou des fichiers traces contenant les octets capturés préalablement sur un réseau
Ethernet.


---

## 2 Code source

### 2.1 file [main.py](src/main.py)

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

### 2.2 file [analyzer.py](src/analyzer.py)

le fichier ’analyzer.py’ est divisé principalement en 2 grandes parties :
- Analyse des octets et extraction des informations via l'appel de la fonction 'analyse_frame_ethernet2'
- Affichage/écriture des informations extraites de la trame

### 2.3 Les fichiers permettant l'analyse d'une trame pour chaque protocol

#### 2.3.1 Couche Laison ([couche_link](src/couche_link))

##### 2.3.1.1 File [protocol_ethernet.py](src/couche_link/protocol_ethernet.py)

Permet l'analyse des différentes type de trame Ethernet (ethernet2 et eternet802.1q).
On a donc principalement 2 fonction `analyse_frame_ethernet2(frame)` et `analyse_frame_ethernet802_1.q(frame)`.
Toutes 2 prennent une liste d'octet ne connenant pas de préambule, de sfd et de fcs.

La fonction `analyse_frame_ethernet(frame, type_frame)` permet l'analyse d'une trame ethernet avec
préambule, sfd et fcs.

Ceux-ci n'analyse que l'entete Ethernet avant de faire appel au protocol de la couche suivante
qu'encapsule cette trame.

#### 2.3.2 Couche Réseau ([couche_network](src/couche_network))

##### 2.3.2.1 File [protocol_ip.py](src/couche_network/protocol_ip.py)

Il me permet d'analyser des packets IPv4 et IPv6 grace au fonction respective `analyse_datagram_ipv4(packet)`
et `analyse_datagram_ipv6(packet)` qui prennent toutes 2 une liste d'octets conntenant l'entete et les données
des protocoles respectifs. Ces 2 fonctions analysent juste l'entete et font appel à un protocol de la couche supérieur
pour l'analyse des données qu'elles contiennent-

##### 2.3.2.2 File [protocol_arp.py](src/couche_network/protocol_arp.py)

Au travers de la fonction `analyse_packet_arp(packet)` permet l'analyse d'un packet ARP.

#### 2.3.3 Couche Transport ([couche_transport](src/couche_transport))

##### 2.3.3.1 File [protocol_icmp.py](src/couche_transport/protocol_icmp.py)

##### 2.3.3.2 File [protocol_tcp.py](src/couche_transport/protocol_tcp.py)

##### 2.3.3.3 File [protocol_udp.py](src/couche_transport/protocol_udp.py)

#### 2.3.4 Couche Application ([couche_application](src/couche_application))

##### 2.3.4.1 File [protocol_dhcp.py](src/couche_application/protocol_dhcp.py)

##### 2.3.4.2 File [protocol_dns.py](src/couche_application/protocol_dns.py)

##### 2.3.4.3 File [protocol_http.py](src/couche_application/protocol_http.py)

##### 2.3.4.4 File [protocol_ftp.py](src/couche_application/protocol_ftp.py)

##### 2.3.4.5 File [protocol_imap.py](src/couche_application/protocol_imap.py)


---

## 3 Format des fichiers contenant les packets

Important : Pour les fichiers contenant les packets, il a été choisit que deux trames successives doivent
etre séparé par au minimum une ligne blanche (ligne vide).


---

## 4 Test

### 4.1 Test du protocol dhcp

Le fichier dhcp.txt contient un exemple de trame dhcp utile pour faire un test. Le fichier
test_dhcp.sh contient un code minimal pour tester le fonctionnement de notre programme.

### 4.2 Test du protocol dns

Le fichier dns.txt contient un exemple de trame dns utile pour faire un test. Le fichier
test_dns.sh contient un code minimal pour tester le fonctionnement de notre programme.

