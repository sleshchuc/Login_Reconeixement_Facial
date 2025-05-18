# Mòduls i llibreries necessàris.
import os
import datetime
import pickle
import tkinter as tk
import cv2
from PIL import Image, ImageTk
import face_recognition
import subprocess
import threading
import util
import re

# Definició de colors per a l'output a la terminal.
Yellow = '\033[1;33m'
Reset = '\033[0m'
Red = '\033[1;31m'
Cyan = '\033[1;36m'


# Classe principal que gestiona la interfície gràfica i el reconeixement facial.
class App:
    def __init__(self):
        # Definició del color del fons i estat inicial per controlar l'estat del vídeo.
        self.bg_color = "#1c1c1c"
        self.video_available = False  

        # Configuracions de la geometria, títol i color de fons.
        self.main_window = tk.Tk()
        self.main_window.geometry("1195x520+350+100")
        self.main_window.title("Login G4 application")
        self.main_window.configure(bg=self.bg_color)

        # Afegit de l'icona del nostre grup a la finestra.
        img_path = "login/img/logo.png"
        image = Image.open(img_path)
        image = image.resize((160, 160))
        self.login_image = ImageTk.PhotoImage(image)
        self.login_img_label = tk.Label(self.main_window, image=self.login_image, bg=self.bg_color, bd=0, highlightthickness=0)
        self.login_img_label.place(x=890, y=30)

        # Configuració del botó d'inici de sessió, aspecte del botó, on se posiciona, estat inicial.
        self.login_button_main_window = util.get_button(self.main_window, 'Inici de sessió', '#0f9650', self.login)
        self.login_button_main_window.place(x=750, y=200)
        self.login_button_main_window.configure(highlightbackground=self.bg_color, state='disabled')

        # Configuració del botó de desconnexió.
        self.logout_button_main_window = util.get_button(self.main_window, 'Desconnecta\'m', '#b31212', self.logout)
        self.logout_button_main_window.place(x=750, y=300)
        self.logout_button_main_window.configure(highlightbackground=self.bg_color, state='disabled') 

        # Configuració del botó de registrament.
        self.register_new_user_button_main_window = util.get_button(self.main_window, 'Registra\'m', '#006798', self.register_new_user)
        self.register_new_user_button_main_window.place(x=750, y=400)
        self.register_new_user_button_main_window.configure(highlightbackground=self.bg_color, state='disabled') 

        # Configuració de l'etiqueta (label) de l'imatge de la webcam.
        self.webcam_label = util.get_img_label(self.main_window)
        self.webcam_label.configure(bg=self.bg_color, bd=0, highlightthickness=0)
        self.webcam_label.place(x=10, y=10, width=700, height=500)
        self.add_webcam(self.webcam_label)

        # Creació del directori db/ (si no existeix ja).
        self.db_dir = './login/db'
        if not os.path.exists(self.db_dir):
            os.mkdir(self.db_dir)
        self.log_path = './login/log.txt'

    # Funció que detecta webcam.
    def try_open_camera(self):
        self.cap = cv2.VideoCapture(0) # Creació de l'objecte de captura de video. Es pot consultar càmera amb la comanda v4l2-ctl --list-devices.

        if not self.cap.isOpened(): # Operador if not per verificar l'apertura de la webcam.
            print(f"{Yellow}[INFO] No s'ha detectat cap webcam disponible. {Red}És probable que no hi hagi cap webcam connectada.{Reset}") 
            self._label.configure(text="Esperant connexió amb la webcam...",
                                   fg="white", font=("Arial", 16), image='', anchor='center') # Missatge a l'etiqueta de la webcam.
            self._label.after(5000, self.try_open_camera)  # Reintenta cada 5 segons (5000 ms)
            return

        print(f"{Cyan}[INFO] Webcam detectada correctament. Iniciant vídeo...{Reset}") # Missatge a la terminal.
        self.process_webcam() # Crida al mètode self.process_webcam()

    # Funció que obri la webcam detectada.
    def add_webcam(self, label):
        self._label = label
        self.try_open_camera()

    # Funció que controla en temps reial el vídeo.
    def process_webcam(self):
        ret, frame = self.cap.read()  # Captura el frame de la càmera (ret indica si és exitosa).

        if not ret or frame is None or not frame.any(): # Comprova si la captura ha fallat o el frame està buit (frame.any mira si tots els píxels son zero).

            # Si anteriorment el vídeo estava disponible, es mostra un missatge d'error i es desactiven les funcionalitats dels botons.
            if self.video_available:
                print(f"{Yellow}[INFO] La webcam ha deixat d'enviar vídeo.{Red} Es desactiven les accions d'usuari.{Reset}") # Missatge d'error en terminal.
            self.video_available = False
            self.login_button_main_window.configure(state='disabled')
            self.logout_button_main_window.configure(state='disabled')
            self.register_new_user_button_main_window.configure(state='disabled')
            self._label.configure(text="S'ha perdut la connexió amb la webcam o no s'està rebent vídeo...", 
                                  fg="white", font=("Arial", 14), image='') # Missatge d'error en l'etiqueta de la webcam.
            self._label.after(1500, self.process_webcam) # Es configura un nou intent per reconnectar en 1.5 segons (1500 ms).
            return

        # Si anteriorment no hi havia vídeo però ara sí que hi ha, s'activa tot de nou.
        if not self.video_available:
            print(f"{Cyan}[INFO] S'està rebent vídeo correctament.{Reset}")
            self.login_button_main_window.configure(state='normal')
            self.logout_button_main_window.configure(state='normal')
            self.register_new_user_button_main_window.configure(state='normal')
            self._label.configure(text="")  # Neteja text de l'etiqueta de la webcam, si hi havia missatge.

        # S'actualitza l'estat de False a True per indicar la disponibilitat del vídeo.
        self.video_available = True

        self.most_recent_capture_arr = frame # Es guarda el fotograma capturat la variable frame.
        img_ = cv2.cvtColor(self.most_recent_capture_arr, cv2.COLOR_BGR2RGB) # Converteix el frame de BGR a RGB (del format OpenCV a a l'estàndard).
        self.most_recent_capture_pil = Image.fromarray(img_) # Converteix el frame a un objecte d'imatge de la llibreria PIL (Pillow).
        imgtk = ImageTk.PhotoImage(image=self.most_recent_capture_pil) # Converteix l'objecte PIL a un format que Tkinter pot mostrar (PhotoImage).
        self._label.imgtk = imgtk # Assigna l'objecte PhotoImage a l'etiqueta.
        self._label.configure(image=imgtk) # Actualitza el label per mostrar el nou frame capturat.
        self._label.after(20, self.process_webcam) # Es configura una nova actualització en 20 mil·lèsimes.

    # Funció que gestiona els processos a l'iniciar sessió.
    def login(self):
        # Reconeixement de l'usuari (funció recognize() del util.py) utilitzant l'últim frame capturat (most_recent_capture_arr) i el directori especificat (db_dir).
        name = util.recognize(self.most_recent_capture_arr, self.db_dir) 

        # Comprova si el nom retornat és "unknown_person" o "no_persons_found", indicant que no s'ha reconegut cap persona.
        if name in ['unknown_person', 'no_persons_found']:
            util.msg_box('Ups...', 'Usuari desconegut. Perfavor, registrat amb un nou usuari o prova un altre cop.')
        
        # Si es reconeix a la persona, se li dona un missatge de benvinguda i es guarda en un fitxer de logs.
        else:
            util.msg_box('Hey!', f'Et donem la benvinguda, {name}.')
            with open(self.log_path, 'a') as f:
                f.write(f'{name} | {datetime.datetime.now()} | Logged in\n')
            self.main_window.iconify() # Es minimitza la finestra principal 
            threading.Thread(target=self.run_script, daemon=True).start() # S'inicia un thread per executar l'script.

    # Funció que obri l'aplicació de Pentesting realitzada anteriorment.
    def run_script(self):
        script_path = "gui-app/gui-app.py" 
        self.process = subprocess.Popen(['python3', script_path], preexec_fn=os.setpgrp)
                
    # Funció que s'encarrega de desconnecta-se de l'aplicació.
    def logout(self):
        # Reconeixement de l'usuari utilitzant l'últim frame capturat i el directori especificat (db_dir).
        name = util.recognize(self.most_recent_capture_arr, self.db_dir)

        # Comprova si el nom retornat és "unknown_person" o "no_persons_found", indicant que no s'ha reconegut cap persona.
        if name in ['unknown_person', 'no_persons_found']:
            util.msg_box('Ups...', 'Usuari desconegut. Perfavor, registrat amb un nou usuari o prova un altre cop.')
        
        # Si es reconeix a la persona, se li dona un missatge de comiat i es guarda en un fitxer de logs.
        else:
            util.msg_box('Fins aviat!', f'Adéu {name}, fins la pròxima!')
            with open(self.log_path, 'a') as f:
                f.write(f'{name} | {datetime.datetime.now()} | Logged out\n')
            self.main_window.destroy() # Es tanca la finestra i aplicació.

    # Aquesta funció s'encarrega de crear una nova finestra en què l'usuari pot registrar-se.
    def register_new_user(self):
        
        # Creació de la nova finestra, amb les mides i posicions, el títol i el colord e fons.
        self.register_new_user_window = tk.Toplevel(self.main_window)
        self.register_new_user_window.geometry("1170x520+350+100")
        self.register_new_user_window.title("Register G4 application")
        self.register_new_user_window.configure(bg=self.bg_color)

        # Creació del botó d'"Accepto", indicant el color del botó i del fons, i la seva posició.
        self.accept_button_register_new_user_window = util.get_button(
            self.register_new_user_window, 'Accepto', '#0f9650', self.accept_register_new_user)
        self.accept_button_register_new_user_window.place(x=750, y=300)
        self.accept_button_register_new_user_window.configure(highlightbackground=self.bg_color)

        # Creació del botó de "Torna enrere...", indicant el color del botó i del fons, i la seva posició.
        self.try_again_button_register_new_user_window = util.get_button(
            self.register_new_user_window, 'Torna enrere...', '#b31212', self.try_again_register_new_user)
        self.try_again_button_register_new_user_window.place(x=750, y=400)
        self.try_again_button_register_new_user_window.configure(highlightbackground=self.bg_color)

        self.capture_label = util.get_img_label(self.register_new_user_window)
        self.capture_label.configure(bg=self.bg_color, bd=0, highlightthickness=0)
        self.capture_label.place(x=10, y=0, width=700, height=500)

        # S'afegeix una imatge a l'etiqueta.
        self.add_img_to_label(self.capture_label)

        # Creació d'un camp de text per introduir el nom d'usuari, posicionant-lo en la finestra.
        self.entry_text_register_new_user = util.get_entry_text(self.register_new_user_window)
        self.entry_text_register_new_user.configure(bg="#eaeae9", width=13)
        self.entry_text_register_new_user.place(x=755, y=150)

        # Creació d'una etiqueta per demanar el nom d'usuari.
        self.text_label_register_new_user = util.get_text_label(
            self.register_new_user_window, 'Indica el nom d\'usuari:')
        self.text_label_register_new_user.configure(bg=self.bg_color, fg='white')
        self.text_label_register_new_user.place(x=750, y=70)

    # Funció que tanca la finestra de registre en tornar enrere.
    def try_again_register_new_user(self):
        self.register_new_user_window.destroy()

    # Funció que converteix la imatge a un format compatible amb Tkinter.
    def add_img_to_label(self, label):
        imgtk = ImageTk.PhotoImage(image=self.most_recent_capture_pil) # Conversió de l'última captura.

        # Assigna la imatge convertida a l'etiqueta i desa la captura actual com a nova imatge per al registre.
        label.imgtk = imgtk
        label.configure(image=imgtk)
        self.register_new_user_capture = self.most_recent_capture_arr.copy()

    # Funció que inicia el main loop de la finestra, mantenint l'aplicació activa.
    def start(self):
        self.main_window.mainloop()

    # Funció que gestiona les accions al acceptar.
    def accept_register_new_user(self):

        # S'obté el text del camp de registre (nom d'usuari) i s'eliminen espais innecessaris.
        name = self.entry_text_register_new_user.get(1.0, "end-1c").strip()

        # Es verifica si el nom és vàlid: que no estigui buit, no més llarg que 16 caràcters, i només lletres.
        if not name or len(name) > 16 or not re.match(r'^[a-zA-Z]+$', name):
            util.msg_box("Ups...", "Has d'introduir un nom d'usuari vàlid (màxim 16 lletres, només lletres).")
            return

        # Es crea el camí per a un arxiu de l'usuari (.pickle) utilitzant el nom introduït i comprova si el fitxer de l'usuari ja existeix.
        user_file_path = os.path.join(self.db_dir, f'{name}.pickle')
        if os.path.exists(user_file_path):
            util.msg_box("Ups...", f"L'usuari \"{name}\" ja existeix.\nSi vols actualitzar el teu usuari, contacta amb l'administrador.")
            return

        # S'intenta obtenir l'encoding de la cara de la imatge capturada per al registre.
        encodings = face_recognition.face_encodings(self.register_new_user_capture)
        
        # Si no es detecta cap cara, mostra un missatge d'error.
        if not encodings:
            util.msg_box("Ups...", "No s'ha detectat cap cara a la imatge. Intenta-ho de nou amb una cara visible i ben il·luminada.")
            return

        # S'obté el primer embedding (encodificació) de la cara detectada, i el desa en un fitxer per a l'usuari.
        embeddings = encodings[0]
        with open(user_file_path, 'wb') as file:
            pickle.dump(embeddings, file) # Guarda la codificación facial en un archivo.

        # Es mostra un missatge indicant que el registre ha sigut correcte, i seguidament es tanca la finestra.
        util.msg_box('Perfecte!', f'L\'usuari {name} ha sigut registrat correctament !')
        self.register_new_user_window.destroy()

if __name__ == "__main__":
    # Inici de l'aplicació
    app = App()
    app.start()
