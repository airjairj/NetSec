# NetSec

Tool/
│
├── core/
│   ├── scanner.py            # Gestione del rilevamento delle reti (sniffing)
│   ├── deauth.py             # FIX REQUIRED Gestione dell'attacco di deautenticazione
│   ├── cracker.py            # TODO Gestione del cracking WPA/WPA2
│   ├── monitor_mode.py       # TODO Configurazione della scheda wireless in modalità monitor
│   └── utils.py              # TODO Funzioni di utilità comuni (gestione dei pacchetti, parsing)
│
├── data/
│   └── wordlists/            # Directory per i dizionari di password (file .txt)
│
├── tests/
│   ├── test_scanner.py       # TODO Test per lo scanner
│   ├── test_deauth.py        # TODO Test per il deauth
│   ├── test_cracker.py       # TODO Test per il modulo di cracking
│
├── main.py                   # Punto di ingresso principale per avviare il tool
├── README.md                 # Documentazione del progetto
└── requirements.txt          # Dipendenze del progetto (es. Scapy, PyCryptodome, ecc.)
