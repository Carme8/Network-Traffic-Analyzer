from scapy.all import *  # ANALIZZA TRAFFICO RETE-> Sniffa,Invia,Analizza i pachetti.
from collections import defaultdict  # FORNISCE SPECIALI CONTENITORI PER LA GESTIONE DATI 
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import tkinter.font as tkFont
import threading  # ESEGUE LO SNIFFING IN UN THREAD SEPARATO EVITANDO BLOCCHI

class NetworkAnalyzer:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.suspicious_ips = set()
        self.running = False
        self.results_text = None
        self.threshold = 100  # SOGLIA CONFIGURABILE
        self.protocol_filter = None  # FILTRO PROTOCOLLO
        self.start_time = 0  # TEMPO INIZIO ANALISI

    def packet_callback(self, packet):
        if IP in packet:
            if self.protocol_filter and self.protocol_filter.lower() not in str(packet):
                return

            src_ip = packet[IP].src
            self.packet_counts[src_ip] += 1

            if self.packet_counts[src_ip] > self.threshold:
                self.suspicious_ips.add(src_ip)
                self.update_results(f"Comportamento sospetto rilevato: {src_ip}", "red")

    def update_results(self, message, color="black"):
        # Usa after() per eseguire il comando nel thread principale
        if self.results_text:
            self.root.after(0, self._update_results, message, color)

    def _update_results(self, message, color="black"):
        if self.results_text:
            self.results_text.insert(tk.END, message + "\n", ("msg", color))
            self.results_text.see(tk.END)
            if len(self.results_text.get("1.0", tk.END)) > 1000:  # GESTIONE ECCEDENZA DATI 
                self.results_text.delete("1.0", "2.0")

    def start_sniffing(self, interface='en0', duration=60):
        self.running = True
        self.start_time = time.time()
        self.update_results("Avvio analisi del traffico di rete...")
        sniff(iface=interface, prn=self.packet_callback, store=0, timeout=duration)
        self.running = False
        self.update_results("Analisi completata.")
        self.report()
        self.update_results("Analisi conclusa.", "green")

    def report(self):
        report_message = "\n---- Report Finale ----\n"
        if self.suspicious_ips:
            report_message += "IP Sospetti rilevati:\n"
            for ip in self.suspicious_ips:
                report_message += f"- {ip}: {self.packet_counts[ip]} pacchetti\n"
        else:
            report_message += "Nessun comportamento sospetto rilevato."
        
        self.update_results(report_message)
        self.save_report(report_message)

    def save_report(self, report_message):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", 
                                                   filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if file_path:
            with open(file_path, 'w') as f:
                f.write(report_message)
            self.update_results(f"Report salvato in: {file_path}", "green")
            self.close_program()

    def launch_gui(self):
        self.root = tk.Tk()
        self.root.title("Network Traffic Analyzer")

        custom_font = tkFont.Font(family="JetBrainsMonoNL-Light", size=12)

        tk.Label(self.root, text="Interfaccia di rete:", font=custom_font).pack(pady=5)
        self.interface_entry = tk.Entry(self.root, font=custom_font)
        self.interface_entry.pack(pady=5)

        tk.Label(self.root, text="Durata (secondi):", font=custom_font).pack(pady=5)
        self.duration_entry = tk.Entry(self.root, font=custom_font)
        self.duration_entry.pack(pady=5)

        tk.Label(self.root, text="Soglia IP sospetti:", font=custom_font).pack(pady=5)
        self.threshold_entry = tk.Entry(self.root, font=custom_font)
        self.threshold_entry.pack(pady=5)
        self.threshold_entry.insert(0, str(self.threshold))

        tk.Label(self.root, text="Filtro Protocollo (Es. TCP, UDP):", font=custom_font).pack(pady=5)
        self.protocol_entry = tk.Entry(self.root, font=custom_font)
        self.protocol_entry.pack(pady=5)

        start_button = tk.Button(self.root, text="Avvia Analisi", command=self.start_analysis, font=custom_font)
        start_button.pack(pady=10)

        self.results_frame = tk.Frame(self.root)
        self.results_frame.pack(pady=10)

        self.results_text = scrolledtext.ScrolledText(self.results_frame, width=50, height=10, font=custom_font, wrap=tk.WORD)
        self.results_text.tag_configure("msg", foreground="black")
        self.results_text.pack(side=tk.TOP)

        self.root.mainloop()

    def start_analysis(self):
        if not self.duration_entry.get().isdigit() or not self.threshold_entry.get().isdigit():
            self.update_results("Errore: Inserisci una durata e soglia validi (numeri interi).", "red")
            return

        duration = int(self.duration_entry.get())
        self.threshold = int(self.threshold_entry.get())
        self.protocol_filter = self.protocol_entry.get().strip()

        threading.Thread(target=self.start_sniffing, args=(self.interface_entry.get(), duration)).start()
        self.update_results("Analisi avviata. Controlla i risultati nell'area di testo.")

    def close_program(self):
        self.root.quit()  # Questo chiude la finestra Tkinter


if __name__ == "__main__":
    analyzer = NetworkAnalyzer()
    analyzer.launch_gui()

