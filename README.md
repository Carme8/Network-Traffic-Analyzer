# Network Traffic Analyzer
Strumento che consente di analizzare il traffico di rete in tempo reale, monitorando e registrando gli indirizzi IP sospetti in base al numero di pacchetti che inviano sulla rete.
Utile per gli amministratori di sistema e i professionisti della sicurezza informatica, poiché permette di rilevare potenziali attività malevole o anomale nei flussi di rete, 
come attacchi DDoS (Distributed Denial of Service) o tentativi di accesso non autorizzato.

#  Funzionalità principali:
    • Monitoraggio del traffico di rete.
    • Utilizzo della libreria scapy per monitorare e analizzare i pacchetti di rete in tempo reale.
    • Possibilità di configurare un'interfaccia di rete specifica da monitorare:
              - macOS: en0, en1 (per le interfacce di rete principali), lo0 (loopback)
              - Linux (Ubuntu): eth0, enp3s0 (cablata), wlan0, wlp2s0 (wireless), lo (loopback)
              - Windows: Ethernet, Wi-Fi (o simili, dipende dalle interfacce specifiche)
              
    • Esegue un monitoraggio continuo per una durata predefinita, durante la quale i pacchetti vengono catturati e analizzati.

# Filtraggio dei pacchetti:

    • È possibile impostare un filtro per monitorare solo i pacchetti di un determinato protocollo: TCP, UDP, ICMP.
    
# Rilevamento degli IP sospetti:

    • Il programma conta il numero di pacchetti inviati da ciascun indirizzo IP.
    • Se un determinato IP supera una soglia configurabile di pacchetti (ad esempio 100 pacchetti), 
    viene considerato sospetto e aggiunto a una lista di IP sospetti.

# Salvataggio dei report:
  • Al termine dell'analisi, lo strumento genera un report che elenca tutti gli IP sospetti rilevati e il numero di pacchetti inviati.
  Il report può essere salvato come file di testo, consentendo agli utenti di conservarlo per un'analisi futura o per reportistica.
  
 <img width="358" alt="Screenshot 2024-12-16 alle 15 33 45" src="https://github.com/user-attachments/assets/0d795ee0-d2e4-4380-9caa-fba2e65029d7" />

# Dipendenze:
• È richiesto Python 3.13.0.

• Sono richiesti anche i moduli: Scapy, Collections, Threading, Tkinter, Messagebox.
