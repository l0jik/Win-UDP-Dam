# WIN-UDP-Dam
Outgoing UDP packets disturbance

Win-UDP-Dam script v0.1
Author: l0jik
Lang: ENG-IT


First Public Repository - be kind, therefore!

ENG

— ABOUT - 
The purpose of these scripts for Windows and Linux is to rewrite the headers of
UDP outgoing packets.
Such a disturbance creates a messy signal for spywares, thus interfering with 
Remote Controls and Desktop Sharing.

All outgoing UDP packets will be modified, so that the user will not be able to
communicate through live calls, both audio and video.

It’s still an ongoing project, experimental in a way. But, had you ever been spied upon,
It comes quite handy as a solution.

IT

Lo scopo di questi script per Windows e Linux è di riscrivere gli header
Dei pacchetti UDP in uscita.
Un tale disturbo determina un segnale disordinato per gli spyware, pertanto
Interferendo con i Remote Control e il Desktop Sharing.

Tutti i pacchetti UDP in uscita verranno modificati, perciò l’utente non sarà in grado
Di comunicare via call, sia audio che video.

E’ un progetto ancora in sviluppo, in un certo senso sperimentale. Ma, qualora
siate mai stati spiati, è una soluzione piuttosto comoda.

- USAGE -

python -m pip install psutil

python win-udp-dam.py status
python win-udp-dam.py enable
python win-udp-dam.py disable



