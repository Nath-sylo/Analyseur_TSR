========================
INSTALLATION
========================

	Faire la commande 'make' pour installer l'analyseur de trames.
	
	L'éxécutable sera créé dans le dossier "bin".


========================
ÉXÉCUTION
========================

	L'analyseur peut être lancé depuis le dossier parent (celui contenant ce fichier) avec la commande :
		'./bin/analyseur'

	L'analyseur peut également être démarré depuis le répertoire "bin".Pour cela, il faut rentrer les commandes :
		'cd bin'
		'./analyseur'

========================
OPTIONS
========================

	L'analyseur peut-être démarré avec trois options différentes : v, o, i

		* -v <[1|2|3]> : l'option de verbosité '-v' détermine le niveau de verbosité avec lequel les trames seront 					affichées. Un niveau de verbosité de <1> affichera les trames en une seule ligne ; le niveau de 				verbosité <2> affichera chaque de trame de telle sorte que chaque protocole impliqué dans la 					trame sera décrit en 1 ligne ; le niveau de verbosité <3> affiche la trame dans son intégralité. 					Si cette option n'est pas activée, l'analyseur renverra une analyse en verbosité 3.


		* -o <fichier> : l'option d'analyse offline '-o' permet d'analyser une trace contenue dans un fichier. Cette 					option est compatible avec l'option de verbosité. Il n'y a aucun intérêt à utiliser cette option 					avec l'option de choix de l'interface d'écoute.


		* -i <interface> : l'option de choix d'interface '-i' permet de choisir l'interface sur laquelle les trames 					seront analysées. L'argument est le nom de l'interface (ex : eth0). Cette option est inutile avec 					l'option d'analyse offline. Si cette option n'est pas activée, l'analyseur déterminera lui-même 				une interface sur laquelle il peut écouter.

========================
EXEMPLES D'UTILISATION
========================

* En étant situé dans le répertoire parent :

	./bin/analyseur
	
	./bin/analyseur -v 1

	./bin/analyseur -v 2 -o trame_udp.cap

	./bin/analyseur -v 3 -i eth2

* En étant situé dans le répertoire "bin" :

	./analyseur

	./analyseur -v 1 -o trame_tcp.cap

	./analyseur -v 2

	./analyseur -i eth1


========================
REMARQUE
========================

	Il est important de noter que selon la session de l'utilisateur, les commandes d'éxécution du programme doivent être précédées de la commande 'sudo' !
	
	Par exemple : 
		'sudo ./bin/analyseur -v 3 -i eth1'
