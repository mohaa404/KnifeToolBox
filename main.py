import os
import subprocess
import paramiko
import nmap
import re
import matplotlib.pyplot as plt  # Importation de la bibliothèque Matplotlib pour la création de graphiques
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup
from kivy.uix.image import AsyncImage
from kivy.animation import Animation
from kivy.core.window import Window
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image as ReportImage
from reportlab.lib.styles import getSampleStyleSheet

class KnifeToolboxApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ssh_results = ""  # Stocke les résultats de la tentative de connexion SSH
        self.vulnerability_results = []  # Stocke les résultats de la détection de vulnérabilités
        self.styles = getSampleStyleSheet()  # Obtient les styles de base pour les rapports PDF
        self.title_label = None
        self.instructions_label = None
        self.host_ip = None
        self.nm = nmap.PortScanner()  # Initialisation du scanner de ports Nmap
        self.num_discovered_hosts = 0  # Nombre d'hôtes découverts
        self.num_detected_vulnerabilities = 0  # Nombre de vulnérabilités détectées
        self.num_open_ports = 0  # Nombre de ports ouverts
        self.open_ports = []  # Liste des ports ouverts
        self.discovered_hosts = []  # Liste des hôtes découverts

    def build(self):
        layout = BoxLayout(orientation='vertical')

        # Crée une étiquette pour les instructions
        self.instructions_label = Label(
            text="\n Tips :\n1. Discover network -> Réseaux/XX (172.16.77.0/24) \n2. Port Scan -> @IP (172.16.77.100)  \n3. Vuln -> @IP (172.16.77.100) \n Developed by @Mohaa\n",
            color=(0.3, 0.3, 0.3, 1)
        )
        layout.add_widget(self.instructions_label)

        # Ajoute une image asynchrone GIF à l'interface
        gif_image = AsyncImage(source='img/KnifeToolBox.gif')
        layout.add_widget(gif_image)

        # Crée une étiquette pour le titre de l'application
        self.title_label = Label(text="Knife Tool Box", font_size='27sp', color=(0, 1, 0, 1), size_hint_y=None, height='45dp')
        layout.add_widget(self.title_label)

        # Crée une étiquette et un champ de texte pour l'adresse IP
        ip_label = Label(text="Adresse IP :", color=(0.3, 0.3, 0.3, 1), size_hint_y=None, height='60dp')
        layout.add_widget(ip_label)
        self.ip_entry = TextInput(size_hint=(None, None), size=(200, 30), pos_hint={'center_x': 0.5}, hint_text="@ IP ")
        layout.add_widget(self.ip_entry)

        # Crée une étiquette et un champ de texte pour le nom du rapport
        report_name_label = Label(text="Nom du rapport (Facultatif) :", color=(0.3, 0.3, 0.3, 1), size_hint_y=None, height='60dp')
        layout.add_widget(report_name_label)
        self.report_name_entry = TextInput(size_hint=(None, None), size=(200, 30), pos_hint={'center_x': 0.5}, hint_text="Nom du rapport (facultatif)")
        layout.add_widget(self.report_name_entry)

        # Crée un cadre de boutons pour les actions
        button_frame = BoxLayout(orientation='horizontal')
        layout.add_widget(button_frame)

        # Liste des boutons d'action avec leur texte associé et la fonction à appeler lorsqu'ils sont pressés
        action_buttons = [
            ("Découvrir le réseau", self.discover_network),
            ("Scanner les ports", self.scan_ports),
            ("Détecter les vulnérabilités", self.detect_vulnerabilities),
            ("Générer un rapport", self.generate_report)
        ]
        for text, action in action_buttons:
            button = Button(text=text, on_press=action)
            button_frame.add_widget(button)

        # Bouton pour la tentative de connexion SSH
        ssh_button = Button(text=" Tentative de Connexion SSH", on_press=self.ssh_connect)
        layout.add_widget(ssh_button)

        # Zone de texte pour afficher les résultats
        self.result_text = ScrollView()
        layout.add_widget(self.result_text)

        # Démarre les animations du titre et des instructions
        self.blink_title()
        self.blink_instructions()

        return layout

    # Animation du titre
    def blink_title(self):
        anim = Animation(color=(1, 1, 1, 1), duration=0.8) + Animation(color=(0, 1, 0, 1), duration=0.8)
        anim.repeat = True
        anim.start(self.title_label)

    # Animation des instructions
    def blink_instructions(self):
        anim = Animation(color=(1, 1, 1, 1), duration=0.8) + Animation(color=(0.3, 0.3, 0.3, 1), duration=0.8)
        anim.repeat = True
        anim.start(self.instructions_label)

    # Fonction pour découvrir le réseau
    def discover_network(self, instance):
        ip_address = self.ip_entry.text
        self.host_ip = ip_address
        self.nm.scan(hosts=ip_address, arguments='-sn')

        hosts = [host for host in self.nm.all_hosts()]
        result_text = "Découverte de réseau :\n" + ', '.join(hosts) if hosts else "Aucun hôte découvert."

        self.num_discovered_hosts += len(hosts)
        self.discovered_hosts = hosts

        popup = Popup(title="Résultats de la découverte de réseau", content=Label(text=result_text), size_hint=(None, None), size=(400, 300))
        popup.open()

    # Fonction pour scanner les ports
    def scan_ports(self, instance):
        ip_address = self.ip_entry.text
        self.host_ip = ip_address
        self.nm.scan(hosts=ip_address, arguments='-T4 -F')

        open_ports_data = []  

        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = self.nm[host][proto].keys()
                for port in ports:
                    if self.nm[host][proto][port]["state"] == "open":  
                        service_name = self.nm[host][proto][port]["name"] if "name" in self.nm[host][proto][port] else "Unknown"
                        open_ports_data.append((port, service_name))
                        self.open_ports.append((host, port, service_name))

        result_text = "Ports ouverts :\n" + '\n'.join(f'Port: {port}, Service: {service_name}' for port, service_name in open_ports_data)  

        popup_text = "Ports ouvert : \n"
        for host, port, service_name in self.open_ports:
            popup_text += f"  Host: {host}, \t Port: {port}, Service: {service_name}\n"

        screen_width, screen_height = Window.size
        popup_width = screen_width * 0.8
        popup_height = screen_height * 0.8
        scroll_view = ScrollView()
        label = Label(text=popup_text, size_hint=(None, None), size=(popup_width, popup_height))
        label.bind(size=label.setter('size'))
        scroll_view.add_widget(label)

        popup = Popup(title="Résultats du scan de ports", content=scroll_view, size_hint=(None, None), size=(popup_width, popup_height))
        popup.open()

    # Fonction pour détecter les vulnérabilités
    def detect_vulnerabilities(self, instance):
        ip_address = self.ip_entry.text

        command = ["nmap", "-sV", "--script", "vulners", ip_address]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            result_text = result.stdout
            cve_matches = re.findall(r'(CVE-\d{4}-\d{4,7})', result_text)
            unique_cves = set(cve_matches)  
            num_cves = len(unique_cves)   
            self.num_detected_vulnerabilities += num_cves
            self.vulnerability_results = list(unique_cves)
        else:
            self.vulnerability_results = [f"Erreur lors de la détection de vulnérabilités : {result.stderr}"]

        popup_width = Window.width * 0.8
        popup_height = Window.height * 0.8

        scroll_view = ScrollView()
        label = Label(text='\n'.join(self.vulnerability_results), size_hint=(None, None), size=(popup_width, popup_height))
        label.bind(texture_size=label.setter('size'))
        scroll_view.add_widget(label)

        popup = Popup(title="Résultats de la détection de vulnérabilités", content=scroll_view, size_hint=(None, None), size=(popup_width, popup_height))
        popup.open()

    # Fonction pour générer le rapport
    def generate_report(self, instance):
        report_folder = "report"
        if not os.path.exists(report_folder):
            os.makedirs(report_folder)

        report_name = self.report_name_entry.text.strip() + "_Report.pdf" if self.report_name_entry.text.strip() else "KnifeReport.pdf"
        report_path = os.path.join(report_folder, report_name)

        doc = SimpleDocTemplate(report_path, pagesize=letter)
        report_content = []

        logo_img = ReportImage("img/KnifeToolBox_report.png", width=100, height=100)
        report_content.append(logo_img)
        report_content.append(Paragraph("Rapport de l'outil Knife Tool Box\n\n", self.styles['Title']))
        report_content.append(Paragraph(f"Hôte testé : {self.host_ip}\n\n", self.styles['Normal']))

        ssh_attempts_section = "<b>Résultats des tentatives de connexion SSH</b><br/><br/>"
        for line in self.ssh_results.split("\n"):
            if "Connexion OK" in line:
                # Supprimer les balises de couleur pour les connexions réussies
                line = self.remove_color_tags(line)
                ssh_attempts_section += f"<font color='green'>{line}</font><br/>"
            else:
                ssh_attempts_section += f"{line}<br/>"
        ssh_attempts_section = Paragraph(ssh_attempts_section, self.styles['Normal'])
        report_content.append(ssh_attempts_section)

        vulnerabilities_section = "<b>Résultats de la détection de vulnérabilités</b><br/><br/>"
        for cve in self.vulnerability_results:
            cve_link = f"<a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}'>{cve}</a>"
            vulnerabilities_section += f"{cve_link}<br/>"
        vulnerabilities_section = Paragraph(vulnerabilities_section, self.styles['Normal'])
        report_content.append(vulnerabilities_section)

        open_ports_section = "<b>Résultats du scan de ports</b><br/><br/>"
        for host in self.nm.all_hosts():
            open_ports_section += f'Host : {host}<br/>'
            for proto in self.nm[host].all_protocols():
                open_ports_section += f'Protocol : {proto}<br/>'
                ports = self.nm[host][proto].keys()
                for port in ports:
                    open_ports_section += f'Port : {port} State : {self.nm[host][proto][port]["state"]}<br/>'
        open_ports_section = Paragraph(open_ports_section, self.styles['Normal'])
        report_content.append(open_ports_section)

        discovered_hosts_section = "<b>Résultats de la découverte de réseau</b><br/><br/>"
        for host in self.discovered_hosts:
            discovered_hosts_section += f'Hôte découvert : {host}<br/>'
        discovered_hosts_section = Paragraph(discovered_hosts_section, self.styles['Normal'])
        report_content.append(discovered_hosts_section)

        categories = ['Hosts découverts', 'Vulnérabilités détectées', 'Ports ouverts']
        data = [self.num_discovered_hosts, self.num_detected_vulnerabilities, len(self.open_ports)]

        # Couleurs pour les barres du graphique
        colors = ['blue', 'red', 'orange']

        plt.figure(figsize=(6, 4))
        plt.bar(categories, data, color=colors)  # Utilisation des couleurs définies
        plt.xlabel('Catégories')
        plt.ylabel('Nombre')
        plt.title('Résumé des résultats')
        plt_file = os.path.join(report_folder, "result.png")
        plt.savefig(plt_file)
        plt.close()  # Fermer la figure pour éviter l'affichage dans la sortie standard
        report_content.append(ReportImage(plt_file, width=400, height=200))

        doc.build(report_content)

        self.result_text.clear_widgets()
        self.result_text.add_widget(Label(text=f"Rapport généré : {report_path}"))

    # Fonction pour la tentative de connexion SSH
    def ssh_connect(self, instance):
        ip_address = self.ip_entry.text

        usernames = ["admin", "mohaa","msfadmin"]
        passwords = ["msfadmin", "password"]

        login_attempts = []

        for username in usernames:
            for password in passwords:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    ssh.connect(ip_address, username=username, password=password)
                    ssh.close()
                    login_attempts.append(f"[color=00FF00]Connexion OK {username}/{password}[/color]\n")
                except paramiko.AuthenticationException:
                    login_attempts.append(f"Connexion NOK {username}/{password}\n")

        self.ssh_results = "".join(login_attempts)

        popup = Popup(title='Résultats des tentatives de connexion SSH', content=Label(text=self.ssh_results, markup=True), size_hint=(None, None), size=(400, 300))
        popup.open()

    # Fonction pour supprimer les balises de couleur
    def remove_color_tags(self, text):
        # Utilise une expression régulière pour supprimer les balises de couleur
        return re.sub(r'\[/?color.*?\]', '', text)

if __name__ == "__main__":
    KnifeToolboxApp().run()
