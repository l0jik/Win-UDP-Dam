# WIN-UDP-Dam
Outgoing UDP packets disturbance

Win-UDP-Dam script v0.1
Author: l0jik
Lang: ENG-IT


First Public Repository - be kind, therefore!

ENG

- ABOUT 


The purpose of these scripts for Windows and Linux is to block
UDP outgoing packets.
Such a block creates a dam for spywares, thus interfering with 
Remote Controls and Desktop Sharing.

All outgoing UDP packets will be blocked, so that the user will not be able to
communicate through live calls, both audio and video.

It’s still an ongoing project, experimental in a way. But, had you ever been spied upon,
It comes quite handy as a solution.
TO NAVIGATE, remember to enable DNS!

IT

Lo scopo di questi script per Windows e Linux è bloccare i pacchetti UDP in uscita.
Un tale blocco  determina una difesa contro gli spyware, pertanto
interferendo con i Remote Control e il Desktop Sharing.

Tutti i pacchetti UDP in uscita verranno fermati, perciò l’utente non sarà in grado
Di comunicare via call, sia audio che video.

E’ un progetto ancora in sviluppo, in un certo senso sperimentale. Ma, qualora
siate mai stati spiati, è una soluzione piuttosto comoda.
PER NAVIGARE, ricorda di abilitare il DNS!

- DEPENDENCIES


python -m pip install psutil

- USAGE (Run Powershell as Administrator)-

py win-udp-dam.py status

py win-udp-dam.py enable

py win-udp-dam.py disable

- ENABLE DNS

py win-udp-dam.py enable --allow-dns



