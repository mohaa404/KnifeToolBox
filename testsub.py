from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.popup import Popup
from kivy.uix.image import AsyncImage
from kivy.animation import Animation
from kivy.clock import Clock
import subprocess
import nmap
from kivy.core.window import Window

class KnifeToolboxApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.report_results = ""
        self.styles = None
        self.title_label = None
        self.instructions_label = None
        self.host_ip = None

    def build(self):
        layout = BoxLayout(orientation='vertical')

        self.instructions_label = Label(
            text="\n Tips :\n1. Discover network -> Réseaux/XX (172.16.77.0/24) \n2. Port Scan -> @IP (172.16.77.100)  \n3. Vuln -> @IP (172.16.77.100) \n Developed by @Mohaa\n",
            color=(0.3, 0.3, 0.3, 1)
        )
        layout.add_widget(self.instructions_label)

        gif_image = AsyncImage(source='img/KnifeToolBox.gif')
        layout.add_widget(gif_image)

        self.title_label = Label(text="Knife Tool Box", font_size='27sp', color=(0, 1, 0, 1), size_hint_y=None, height='45dp')
        layout.add_widget(self.title_label)

        ip_label = Label(text="Adresse IP :", color=(0.3, 0.3, 0.3, 1), size_hint_y=None, height='60dp')
        layout.add_widget(ip_label)

        self.ip_entry = TextInput(size_hint=(None, None), size=(200, 30), pos_hint={'center_x': 0.5}, hint_text="@ IP ")
        layout.add_widget(self.ip_entry)

        self.report_name_entry = TextInput(size_hint=(None, None), size=(200, 30), pos_hint={'center_x': 0.5}, hint_text="Nom du rapport (facultatif)")
        layout.add_widget(self.report_name_entry)

        button_frame = BoxLayout(orientation='horizontal')
        layout.add_widget(button_frame)

        action_buttons = [
            ("Découvrir le réseau", self.discover_network),
            ("Scanner les ports", self.scan_ports),
            ("Détecter les vulnérabilités", self.detect_vulnerabilities),
            ("Générer un rapport", self.generate_report)
        ]
        for text, action in action_buttons:
            button = Button(text=text, on_press=action)
            button_frame.add_widget(button)

        ssh_button = Button(text=" Tentative de Connexion SSH", on_press=self.ssh_connect)
        layout.add_widget(ssh_button)

        self.result_text = ScrollView()
        layout.add_widget(self.result_text)

        self.blink_title()
        self.blink_instructions()

        return layout

    def blink_title(self):
        anim = Animation(color=(1, 1, 1, 1), duration=0.8) + Animation(color=(0, 1, 0, 1), duration=0.8)
        anim.repeat = True
        anim.start(self.title_label)

    def blink_instructions(self):
        anim = Animation(color=(1, 1, 1, 1), duration=0.8) + Animation(color=(0.3, 0.3, 0.3, 1), duration=0.8)
        anim.repeat = True
        anim.start(self.instructions_label)

    def discover_network(self, instance):
        ip_address = self.ip_entry.text
        self.host_ip = ip_address
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_address, arguments='-sn')

        hosts = [host for host in nm.all_hosts()]
        result_text = "Découverte de réseau :\n" + ', '.join(hosts) if hosts else "Aucun hôte découvert."

        self.report_results += result_text + "\n"

        popup = Popup(title="Résultats de la découverte de réseau", content=Label(text=result_text), size_hint=(None, None), size=(400, 300))
        popup.open()

    def scan_ports(self, instance):
        ip_address = self.ip_entry.text
        self.host_ip = ip_address
        nm = nmap.PortScanner()
        nm.scan(hosts=ip_address, arguments='-p 22,80,443')

        result_text = "Scan de ports :\n"

        for host in nm.all_hosts():
            result_text += f'Host : {host}\n'
            for proto in nm[host].all_protocols():
                result_text += f'Protocol : {proto}\n'
                ports = nm[host][proto].keys()
                for port in ports:
                    result_text += f'Port : {port} State : {nm[host][proto][port]["state"]}\n'

        self.report_results += result_text + "\n"

        popup = Popup(title="Résultats du scan de ports", content=Label(text=result_text), size_hint=(None, None), size=(500, 400))
        popup.open()

    def detect_vulnerabilities(self, instance):
        ip_address = self.ip_entry.text

        # Exécuter la commande nmap pour détecter les vulnérabilités
        command = ["nmap", "-sV", "--script", "vulners", ip_address]
        result = subprocess.run(command, capture_output=True, text=True)

        if result.returncode == 0:
            result_text = result.stdout
            # Filtrer les résultats à partir de la ligne "PORT STATE SERVICE VERSION"
            start_index = result_text.find("PORT STATE SERVICE VERSION")
            if start_index != -1:
                result_text = result_text[start_index:]
        else:
            result_text = f"Erreur lors de la détection de vulnérabilités : {result.stderr}"

        # Obtenir la taille de l'écran
        screen_width, screen_height = Window.size

        # Définir la taille de la popup en fonction de la taille de l'écran
        popup_width = screen_width * 0.8
        popup_height = screen_height * 0.8

        # Créer un widget ScrollView pour afficher le texte résultant
        scroll_view = ScrollView()
        label = Label(text=result_text, size_hint=(None, None), size=(popup_width, popup_height))
        label.bind(texture_size=label.setter('size'))
        scroll_view.add_widget(label)

        # Créer une popup avec le widget ScrollView
        popup = Popup(title="Résultats de la détection de vulnérabilités", content=scroll_view, size_hint=(None, None), size=(popup_width, popup_height))
        popup.open()

    def generate_report(self, instance):
        # Votre code pour générer le rapport
        pass

    def ssh_connect(self, instance):
        # Votre code pour la tentative de connexion SSH
        pass

if __name__ == "__main__":
    KnifeToolboxApp().run()
