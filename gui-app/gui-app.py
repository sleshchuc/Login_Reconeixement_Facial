import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, scrolledtext
import subprocess
import sys
import shodan
import requests
from bs4 import BeautifulSoup
import telegram
import logging
import geoip2.database
import tkinter as tk
from tkinter import ttk
import threading
import _thread
from ttkbootstrap import Style
from ttkbootstrap.constants import *
import tkinter as tk
from tkinter import ttk
import re
import warnings
import asyncio
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from telegram.error import TelegramError


def buscar_shodan(dominio):
    url = f'https://www.shodan.io/search?query={dominio}'
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        resultados = [a.text.strip() for a in soup.find_all('a', href=True) if '/host/' in a['href']]

        return "\n".join(resultados) if resultados else "No se encontraron IPs."

    except requests.RequestException as e:
        return f"Error al buscar en Shodan: {e}"

def shodan_Escaneig(ip):
    api = shodan.Shodan('WOrNrrzTqNEvrGqO5J5yl5oBhoLAM8kx')            #Confi-gurem l'API gratuita de shodan.

    try:
        ip_info = api.host(ip)
        nom = ip_info.get('org', 'No disponible')
        ports = ', '.join(str(port) for port in ip_info['ports'])
        resultat = f"Organización: {nom}\nPuertos abiertos: {ports}\n"
        
        comanda = subprocess.run(["nmap", "-p", ports, "-sCV", "-Pn", ip], capture_output=True, text=True, check=True)
        resultat += f"Resultado Nmap:\n{comanda.stdout}"

        return resultat
    except shodan.APIError as e:
        return f"Error con Shodan: {e}"


def analizar_exif(imagen):
    if not imagen:
        return "No se seleccionó ninguna imagen."
    try:
        comanda = subprocess.run(["exiftool", imagen], capture_output=True, text=True)
        return comanda.stdout if comanda.returncode == 0 else "Error analizando la imagen."
    except subprocess.CalledProcessError as e:
        return f"Error a analitzar l'imatge: {e}"



# Clases y funciones de la interfaz gráfica
class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Eines OSINT y de reconeixement principal")
        self.root.geometry("1500x700")
        self.root.resizable(True, True)

        # Aplicar un tema oscuro
        self.style = Style(theme="darkly")

        # Estilo personalizado para el botón con bordes más redondos
        self.style.configure('TButton', 
                            borderwidth=2, 
                            focusthickness=3, 
                            focuscolor='none',
                            roundness=50)  # Aumenta este valor para bordes más redondos

        # Efecto al pasar el ratón
        self.style.map('TButton',
                    background=[('active', '#0056b3')],
                    bordercolor=[('active', 'white')],
                    lightcolor=[('active', '#0056b3')],
                    darkcolor=[('active', '#004085')])

        # Crear el marco principal
        self.main_frame = ttk.Frame(self.root, padding=20)
        self.main_frame.pack(fill="both", expand=True)

        # Título
        ttk.Label(self.main_frame, text="Eines OSINT y de reconeixement principal", font=("Helvetica", 16, "bold")).pack(pady=10)

        # Pestañas de herramientas
        self.tabs = ttk.Frame(self.main_frame)
        self.tabs.pack(pady=10)

# Configurar botones con iconos modernos (usando emojis como placeholders)
        botons = [
        ("⚙ Shodan", self.obrir_shodan),
        ("✉ ExifTool", self.obrir_exif),
        ("⌨ Comandos", self.obrir_comandes),
        ("♚ Eines OSINT", self.obrir_osint),
        ("♠️ Nmap", self.obrir_nmap),
        ("⚯ SSH Audit", self.obrir_ssh),
        ("♦️ Enum4linux", self.obrir_enum4linux),
        ("⚒ TheHarvester", self.obrir_theHarvester),
        ("♞ WhatWeb", self.obrir_whatweb),
]


# Aumentar espaciado entre botones
 

        for i, (text, command) in enumerate(botons):
            btn = ttk.Button(self.tabs, text=text, command=command, style="TButton", width=15)
            btn.grid(row=0, column=i, padx=5, pady=5)

        # Área de resultados
        self.result_text = tk.Text(self.main_frame, height=25, width=100, wrap="word", font=("Courier", 12), bg="blue", bd=5, relief="ridge")
        self.result_text.pack(pady=10, fill=BOTH, expand=True) 

        # Capturar el tancament de la finestra
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        """
        Captura el tancament de la finestra i torna a la pantalla de login.
        """
        result = messagebox.askyesno("Tancar", "Estàs segur que vols sortir?")
        if result:  # Si l'usuari prem 'Sí', torna a la finestra de login
            self.root.destroy()
              # Crida la funció de login per obrir la finestra de login de nou
    def obrir_comandes(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("Executar Comandes")
        ventana.geometry("600x350")
        
        ttk.Label(ventana, text="Comanda:").pack(pady=5)
        entrada = ttk.Entry(ventana, width=40)
        entrada.pack()
        self.label_comanda = ttk.Label(ventana, text="Comanda usada: - Ninguna")
        self.label_comanda.pack(pady=10)
        self.resultado_text = scrolledtext.ScrolledText(ventana, height=10, width=70)
        self.resultado_text.pack(pady=10)

        def executar_comanda(comanda):
            try:
                self.result_text.insert(tk.END, f"\n📢 Executant: {comanda}\n")
                self.result_text.see(tk.END)  # Desplazar el widget de texto al final
                self.label_comanda.config(text=f"Comanda usada: - {comanda}")
                resultat = subprocess.run(comanda, shell=True, capture_output=True, text=True)
                self.resultado_text.delete(1.0, tk.END)  # Limpiar área de resultados antes de mostrar nuevo texto
                self.resultado_text.insert(tk.END, resultat.stdout + "\n")  # Mostrar el resultat

                # Mostrar el resultado del comando
                
                self.result_text.see(tk.END)  # Desplazar el widget de texto al final

                return resultat.stdout                
            except Exception as e:
                # Mensaje de error si algo falla
                self.result_text.insert(tk.END, f"\n❌ Error executant la comanda: {e}\n")
                return f"Error executant la comanda: {e}"
        
        # Botón para ejecutar el comando
        ttk.Button(ventana, text="Executar", command=lambda: self.mostrar_resultat(executar_comanda(entrada.get()),), bootstyle=SUCCESS).pack(pady=10)

    def eliminar_codigos_ansi(self, texto):
        """
        Elimina los códigos de escape ANSI sin aplicar colores.
        """
        # Códigos ANSI que configuran colores
        patron_ansi = re.compile(r'\x1b\[[0-9;]*[m]')
        # Eliminar los códigos ANSI del texto
        texto_limpio = patron_ansi.sub('', texto)
        return texto_limpio

    def mostrar_resultat(self, texto):
        self.result_text.delete(1.0, tk.END)
        texto_limpio = self.eliminar_codigos_ansi(texto)

        # Insertar el texto limpio sin ningún color
        self.result_text.insert(tk.END, texto_limpio)
        self.result_text.see(tk.END)

        
    def obrir_shodan(self):
            ventana = ttk.Toplevel(self.root)
            ventana.title("Shodan")
            ventana.geometry("400x200")

            ttk.Label(ventana, text="Dominio/IP:").pack(pady=5)
            entrada = ttk.Entry(ventana, width=30)
            entrada.pack()

            frame = ttk.Frame(ventana)
            frame.pack(pady=10)
            
            ttk.Button(frame, text="Buscar servei o domini", command=lambda: self.mostrar_resultat(buscar_shodan(entrada.get())), bootstyle=SUCCESS).grid(row=0, column=0, padx=5)
            ttk.Button(frame, text="Escanejar IP", command=lambda: self.mostrar_resultat(shodan_Escaneig(entrada.get())), bootstyle=INFO).grid(row=0, column=1, padx=5)
   


    def obrir_exif(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("ExifTool")
        ventana.geometry("300x150")
        
        def seleccionar_imagen():
            imagen = filedialog.askopenfilename(filetypes=[("Imágenes", "*.jpg *.png *.jpeg *.gif")])
            if imagen:
                self.mostrar_resultat(analizar_exif(imagen))
        
        ttk.Button(ventana, text="Seleccionar Imagen", command=seleccionar_imagen, bootstyle=PRIMARY, width=20).pack(pady=20)

    def obrir_osint(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("Eines OSINT")
        ventana.geometry("400x200")
        
        tools = [
            ("ExifTool", self.obrir_exif),
            ("Sherlock", self.executar_sherlock),
            ("Sublist3r", self.executar_sublist3r),
            ("Instaloader", self.executar_instaloader),
            ("Holehe", self.executar_holehe),
            ("Dnsrecon", self.executar_dnsrecon),
            ("Whois", self.executar_whois),
            ("Photon", self.obrir_photon),
            ("GeoIP", self.obrir_geoip),

        ]
        
        frame = ttk.Frame(ventana)
        frame.pack(pady=20)
        
        for i, (name, cmd) in enumerate(tools):
            row = i // 2
            col = i % 2
            ttk.Button(frame, text=name, command=cmd, bootstyle=PRIMARY, width=15).grid(row=row, column=col, padx=10, pady=5)

    def executar_exiftool(self):
        imagen = filedialog.askopenfilename(filetypes=[("*.*")])
        if imagen:
            result = subprocess.run(["exiftool", imagen], capture_output=True, text=True)
            self.mostrar_resultat(result.stdout or result.stderr)

    def executar_instalodaer(self):
        usuario = simpledialog.askstring("Instaloader", "Nom del perfil d'Instagram:")
        if usuario:
            result = subprocess.run(["instaloader", usuario], capture_output=True, text=True)
            self.mostrar_resultat(result.stdout)



    def executar_sherlock(self):
        usuario = simpledialog.askstring("Sherlock", "Nom d'usuari a buscar per xarxes socials a traves de DB:")
        if usuario:
            result = subprocess.run(["sherlock", usuario], capture_output=True, text=True)
            self.mostrar_resultat(result.stdout)

    def executar_sublist3r(self):
        dominio = simpledialog.askstring("Sublist3r", "Enumerar subdominis d'un domini:")
        if dominio:
            result = subprocess.run(["sublist3r", "-d", dominio], capture_output=True, text=True)
            self.mostrar_resultat(result.stdout)

    def executar_holehe(self):
        email = simpledialog.askstring("Holehe", "Verificar a quins serveis web està registrat el correu electrònic:")
        if email:
            result = subprocess.run(["holehe", email], capture_output=True, text=True)
            self.mostrar_resultat(result.stdout)

    def executar_dnsrecon(self):
        descripcion = '''Anàlisis dels subdominis i servidors de la seva xarxa.'''

        objetivo = simpledialog.askstring("Dnsrecon", descripcion)
        if objetivo:
            result = subprocess.run(["dnsrecon", "-d",objetivo], capture_output=True, text=True)
            self.mostrar_resultat(result.stdout)

    def executar_whois(self):
        dominio = simpledialog.askstring("Whois", "Buscar informació sobre un domini:")
        if dominio:
            result = subprocess.run(["whois", dominio], capture_output=True, text=True)
            self.mostrar_resultat(result.stdout)


    def obrir_nmap(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("Escaneig Nmap")
        ventana.geometry("600x600")

        # Entrada de IP o selección de interfaz
        ttk.Label(ventana, text="IP o Rang:").pack(pady=5)
        self.nmap_ip_entry = ttk.Entry(ventana, width=25)
        self.nmap_ip_entry.pack(pady=5)

        ttk.Label(ventana, text="Interface:").pack(pady=5)
        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.OptionMenu(ventana, self.interface_var, "Selecciona una interface")
        self.interface_menu.pack(pady=5)

        ttk.Button(ventana, text="Recargar Interfaces", command=self.llistar_interfaces).pack(pady=5)

        # Botones de Escaneig
        ttk.Button(ventana, text="Escaneig de hosts", command=self.obtenir_ips_desde_interface).pack(pady=5)
        ttk.Button(ventana, text="Escaneig complet", command=self.executar_nmap_complet).pack(pady=5)
        ttk.Button(ventana, text="Detecció Vulnerabilitats", command=self.executar_nmap_vuln).pack(pady=5)

        # Opciones adicionales
        self.nmap_os_detection = tk.BooleanVar()
        ttk.Checkbutton(ventana, text="Detecció del SO", variable=self.nmap_os_detection).pack()

        self.nmap_service_version = tk.BooleanVar(value=True)
        ttk.Checkbutton(ventana, text="Versió de serveis", variable=self.nmap_service_version).pack()

        self.nmap_aggressive = tk.BooleanVar()
        ttk.Checkbutton(ventana, text="Mode Agresiu", variable=self.nmap_aggressive).pack()

        # Área de resultados
        self.resultado_text = scrolledtext.ScrolledText(ventana, height=10, width=70)
        self.resultado_text.pack(pady=10)

    def llistar_interfaces(self):
        try:
            # Verificar el sistema operativo
            import platform
            sistema = platform.system()

            if sistema == "Windows":
                # Usar ipconfig en Windows
                resultat = subprocess.run(["ipconfig"], capture_output=True, text=True)
                interfaces = set()
                for linea in resultat.stdout.split('\n'):
                    if "Adaptador" in linea:  # En Windows, las interfaces comienzan con "Adaptador"
                        nombre = linea.split(":")[0].strip()
                        interfaces.add(nombre)

            else:
                # Usar ifconfig en Linux/macOS
                resultat = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True)
                interfaces = set()
                for linea in resultat.stdout.split('\n'):
                    if linea and not linea.startswith(" "):  # Las interfaces no tienen espacios al inicio
                        nombre = linea.split(":")[0].strip()
                        interfaces.add(nombre)

            # Actualizar el menú de interfaces
            menu = self.interface_menu['menu']
            menu.delete(0, 'end')
            for iface in interfaces:
                menu.add_command(label=iface, command=tk._setit(self.interface_var, iface))

        except Exception as e:
            messagebox.showerror("Error", f"No s'han pogut obtenir les interfaces: {str(e)}")
            
    def obtenir_ips_desde_interface(self):
        interfaz = self.interface_var.get()
        if interfaz == "Selecciona una interface" or not interfaz:
            messagebox.showerror("Error", "Selecciona una interface vàlida")
            return []

        try:
            # Obtener las IPs de la interfaz
            resultat = subprocess.run(["ip", "-o", "addr", "show", interfaz], capture_output=True, text=True)
            ips = []
            for linea in resultat.stdout.split('\n'):
                if "inet " in linea:
                    partes = linea.split()
                    ip_con_mascara = partes[3]  # La IP con la máscara está en la cuarta columna
                    ip = ip_con_mascara.split('/')[0]  # Extraer la IP sin la máscara
                    ips.append(ip)

                    # Construir el comanda Nmap con -sn (Escaneig de ping)
                    for ip in ips:
                        command = ["nmap", "-sn", ip_con_mascara]
                        resultat = subprocess.run(command, capture_output=True, text=True)

                        # Agregar opciones avanzadas si están seleccionadas
                        if self.nmap_os_detection.get():
                            command.append("-O")  # Detección de sistema operativo
                        if self.nmap_service_version.get():
                            command.append("-sV")  # Versión de servicios
                        if self.nmap_aggressive.get():
                            command.append("-A")   # Modo agresivo

                        # executar Nmap y mostrar el resultat
                        self.executar_comanda_nmap(command)

        except Exception as e:
            messagebox.showerror("Error", f"Error obtenint les IPs de l'interface: {str(e)}")
            return []
        return ips
    async def enviar_resultat(self, ss):
        # Aquí puedes realizar cualquier acción con la sortida
        chat_id = "1668283863"  # Cambia esto según corresponda

    
    # Método para executar el Escaneig completo
    def executar_nmap_complet(self):
        # Obtener las IPs de la interfaz seleccionada o ingresada manualmente
        if self.nmap_ip_entry.get() != "Selecciona una interfaz":
            ips = self.obtenir_ips_desde_interface()
            ip_manual = self.nmap_ip_entry.get()
            ips = [ip_manual] if ip_manual else []

        # Verificar si hay IPs válidas
        if not ips:
            messagebox.showerror("Error", "Has d'introduir una IP o seleccionar una interface")
            return

        # Crear un diccionario para almacenar los puertos abiertos por IP
        self.puertos_abiertos_por_ip = {}

        for ip in ips:
            command = ["nmap", "-p-", "--open",ip]

            if self.nmap_os_detection.get():
                command.append("-O")
            if self.nmap_service_version.get():
                command.append("-sV")
            if self.nmap_aggressive.get():
                command.append("-A")
        # executar el Escaneig
        resultat = subprocess.run(command, capture_output=True, text=True)
        output = resultat.stdout


        print("=== OUTPUT NMAP ===")  # Debug
        print(output)
        print("===================")


        puertos_abiertos = re.findall(r"(\d{1,5})/tcp\s+open", output)
        print("Ports oberts destacats:", puertos_abiertos)  # Debug
        self.mostrar_resultat(output)

        if puertos_abiertos:
            self.puertos_abiertos_por_ip[ip] = puertos_abiertos
            puertos_str = ",".join(puertos_abiertos)

        else:
            self.mostrar_resultat(f"No s'han trobat ports oberts a la direcció: {ip}")

        # Almacenar los puertos abiertos para el análisis de vulnerabilitats
        sortida = resultat.stdout if resultat.returncode == 0 else resultat.stderr
        self.resultado_text.delete(1.0, tk.END)  # Limpiar área de resultados antes de mostrar nuevo texto
        self.resultado_text.insert(tk.END, sortida + "\n")  # Mostrar el resultat


    # Método para executar el análisis de vulnerabilitats cuando el usuario haga clic en el botón
    def executar_nmap_vuln(self):
        if not hasattr(self, 'puertos_abiertos_por_ip') or not self.puertos_abiertos_por_ip:
            messagebox.showerror("Error", "No s'ha realitzat un escaneig de ports prèviament.")
            return

        # Iterar sobre las IPs y puertos abiertos para hacer el análisis de vulnerabilitats
        for ip, puertos_abiertos in self.puertos_abiertos_por_ip.items():
            puertos_str = ",".join(puertos_abiertos)  # Formar la cadena de puertos de cada IP

            command = ["nmap", "-p", puertos_str, "-sV", "--script", "vuln", ip]

            if self.nmap_os_detection.get():
                command.append("-O")
            if self.nmap_aggressive.get():
                command.append("-A")

            # Imprimir el comanda para depuracióng
            print("Comanda vulnerabilitats:", " ".join(command))

            resultat = subprocess.run(command, capture_output=True, text=True)
            
            # Mostrar la sortida completa
            sortida = resultat.stdout
            print("=== OUTPUT VULN ===")
            print(sortida)
            print("=====================")
            
            self.mostrar_resultat(f"Vulnerabilitats para {ip}:\n{sortida}")
            sortida = resultat.stdout if resultat.returncode == 0 else resultat.stderr
            self.resultado_text.delete(1.0, tk.END)  # Limpiar área de resultados antes de mostrar nuevo texto
            self.resultado_text.insert(tk.END, sortida + "\n")  # Mostrar el resultat

    def executar_comanda_nmap(self, command):
        try:
            resultat = subprocess.run(command, capture_output=True, text=True)
            self.mostrar_resultat(resultat.stdout)

            sortida = resultat.stdout if resultat.returncode == 0 else resultat.stderr
            self.resultado_text.delete(1.0, tk.END)  # Limpiar área de resultados antes de mostrar nuevo texto
            self.resultado_text.insert(tk.END, sortida + "\n")  # Mostrar el resultat
        except Exception as e:
            self.resultado_text.insert(tk.END, f"Error ejecutando Nmap: {str(e)}\n")
            messagebox.showerror("Error", f"Error ejecutando Nmap: {str(e)}")

    def obrir_ssh(self):
        ventana = tk.Toplevel(self.root)
        ventana.title("Auditoría SSH")
        ventana.geometry("700x500")

        ttk.Label(ventana, text="Auditar el servei SSH amb l'eina ssh-audit:").pack(pady=5)

        ttk.Label(ventana, text="IP:").pack(pady=5)
        ip_entry = ttk.Entry(ventana)
        ip_entry.pack()

        ttk.Label(ventana, text="Port (22):").pack(pady=5)
        port_entry = ttk.Entry(ventana)
        port_entry.pack()

        self.resultado_text = scrolledtext.ScrolledText(ventana, height=10, width=70)
        self.resultado_text.pack(pady=10)

        def ejecutar_auditoria():
            ip = ip_entry.get().strip()
            port = port_entry.get().strip() or "22" 

            if not ip:
                self.resultado_text.insert(tk.END, "Error: Debes introducir una IP válida.\n")
                return

            try:
                resultado= subprocess.run(["ssh-audit",ip_entry.get(), "-p", port_entry.get() or "22" ], capture_output=True, text=True).stdout
                self.mostrar_resultat(resultado)            
            except Exception as e:
                self.resultado_text.insert(tk.END, f"Error ejecutando ssh-audit: {str(e)}\n")

        ttk.Button(ventana, text="Auditar", command=ejecutar_auditoria).pack(pady=20)


    def obrir_geoip(self):
        ventana = tk.Toplevel(self.root)
        ventana.title("geoIP")
        ventana.geometry("700x500")

        ttk.Label(ventana, text="Geolocaltizar IP:").pack(pady=5)

        ttk.Label(ventana, text="IP:").pack(pady=5)
        ip_entry = ttk.Entry(ventana)
        ip_entry.pack()

        self.resultado_text = scrolledtext.ScrolledText(ventana, height=10, width=70)
        self.resultado_text.pack(pady=10)

        def ejecutar_geoip():

            response = requests.get(f"https://ipinfo.io/{ip_entry.get()}/json")
            data = response.json()
            self.mostrar_resultat(
                f"IP: {ip_entry.get()}\n\n"
                f"Ubicación: {data.get('city')}, {data.get('region')}, {data.get('country')}\n"
                f"Coordenadas: {data.get('loc')}"
)
            
        ttk.Button(ventana, text="Auditar", command=ejecutar_geoip).pack(pady=20)

    def executar_instaloader(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("Instaloader")
        ventana.geometry("300x150")

        ttk.Label(ventana, text="Nom del perfil d'instagram a analitzar:").pack(pady=5)
        ip_entry = ttk.Entry(ventana)
        ip_entry.pack()
                
        ttk.Button(ventana, text="Auditar", command=lambda: self.mostrar_resultat(
            subprocess.run(["instaloader",ip_entry.get()], capture_output=True, text=True).stdout
        ), bootstyle=SUCCESS).pack(pady=20)

    def obrir_enum4linux(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("Enum4linux")
        ventana.geometry("400x150")
        ttk.Label(ventana, text="Posa la l'adreça adïent per fer-li un escaneig al servidor smb:").pack(pady=5)

        ttk.Label(ventana, text="IP:").pack(pady=5)
        ip_entry = ttk.Entry(ventana, width=30)
        ip_entry.pack()
        self.resultado_text = scrolledtext.ScrolledText(ventana, height=10, width=70)
        self.resultado_text.pack(pady=10)

        def executar_enum4linux():
            # executar el comando y obtener la sortida
            ss = subprocess.run(["perl", "/app/enum4linux/enum4linux.pl", "-U", "-o", ip_entry.get()], capture_output=True, text=True).stdout
            self.mostrar_resultat(ss)
            self.resultado_text.delete(1.0, tk.END)  # Limpiar área de resultados antes de mostrar nuevo texto
            self.resultado_text.insert(tk.END, ss + "\n")  # Mostrar el resultat

            # Enviar la sortida a la función asincrónica
            asyncio.run(self.enviar_resultat(ss))

        ttk.Button(ventana, text="Executar Enum4linux", command=executar_enum4linux).pack(pady=10)

    def obrir_theHarvester(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("TheHarvester")
        ventana.geometry("400x250")
        opciones_busqueda = ["google", "bing", "yahoo", "baidu", "duckduckgo", "linkedin", "crtsh", "threatcrowd"]
        ttk.Label(ventana, text="Buscar informació(subdominis, correus, urls, usuaris, etc) sobre un domini:").pack(pady=5)
        self.nom_domini = ttk.Entry(ventana, width=30)
        self.nom_domini.pack()
        ttk.Label(ventana, text="Selecciona un motor de búsqueda:", font=("Arial", 10)).pack(pady=5)

        self.combo_busqueda = ttk.Combobox(ventana, values=opciones_busqueda, state="readonly")
        self.combo_busqueda.pack(pady=5)
        self.combo_busqueda.current(0)  # Seleccionar el primer elemento por defecto

        def executar_theHarvester():
            resultat = subprocess.run(["python3", "/app/theHarvester/theHarvester.py", "-d", self.nom_domini.get(), "-b", self.combo_busqueda.get()], capture_output=True, text=True).stdout
            self.mostrar_resultat(resultat)
        
        ttk.Button(ventana, text="Executar TheHarvester", command=executar_theHarvester).pack(pady=10)
        self.buscador = tk.BooleanVar()
        

    def obrir_whatweb(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("Whatweb")
        ventana.geometry("700x350")

        ttk.Label(ventana, text="Buscar els serveis i versions sobre una aplicació web en actiu: ").pack(pady=5)
        nom_servei = ttk.Entry(ventana, width=30)
        nom_servei.pack()
        self.resultado_text = scrolledtext.ScrolledText(ventana, height=10, width=70)
        self.resultado_text.pack(pady=10)



        def executar_whatweb():
            # executar el comando y obtener la sortida
            resultat = subprocess.run(["whatweb", "--color=never",nom_servei.get()], capture_output=True, text=True).stdout
            self.mostrar_resultat(resultat)
    
        ttk.Button(ventana, text="Executar Whatweb", command=executar_whatweb).pack(pady=10)
        self.buscador = tk.BooleanVar()


        
    def obrir_photon(self):
        ventana = ttk.Toplevel(self.root)
        ventana.title("Photon")
        ventana.geometry("400x250")

        ttk.Label(ventana, text="Extreure URLs, correus i versions sobre un domini ").pack(pady=5)
        nom_servei = ttk.Entry(ventana, width=30)
        nom_servei.pack()

        def remove_ansi_codes(text):
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            return ansi_escape.sub('', text)

        def executar_photon():
            resultado = subprocess.run(["python3", "/app/Photon/photon.py", "-u", nom_servei.get()], capture_output=True, text=True).stdout

            # Limpiar los caracteres ANSI
            resultado_limpio = remove_ansi_codes(resultado)

            # Mostrar el resultado en la interfaz
            self.result_text.configure(font=("Courier", 12))

            self.mostrar_resultat(resultado_limpio)
        
        ttk.Button(ventana, text="Executar TheHarvester", command=executar_photon).pack(pady=10)
        self.buscador = tk.BooleanVar()        
        
# Inicialización de la aplicación
if __name__ == "__main__":
    root = ttk.Window(themename="darkly")
    app = App(root)
    root.mainloop()

