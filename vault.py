import os
import base64
import json
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Arquivos principais
VAULT_FILE = "vault.secure"
SALT_FILE = "vault.salt"
MAX_ATTEMPTS = 3

# Derivação segura de chave
def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Geração ou carregamento do salt
def load_salt():
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)
        with open(SALT_FILE, 'wb') as f:
            f.write(salt)
    else:
        with open(SALT_FILE, 'rb') as f:
            salt = f.read()
    return salt

# Criptografia e descriptografia dos dados
def encrypt_data(fernet, data):
    return fernet.encrypt(json.dumps(data).encode())

def decrypt_data(fernet, token):
    return json.loads(fernet.decrypt(token).decode())

# Carregar e salvar vault criptografado
def load_encrypted_vault(fernet):
    if not os.path.exists(VAULT_FILE):
        return {"vault": {}}
    with open(VAULT_FILE, 'rb') as f:
        encrypted = f.read()
        return decrypt_data(fernet, encrypted)

def save_encrypted_vault(fernet, data):
    encrypted = encrypt_data(fernet, data)
    with open(VAULT_FILE, 'wb') as f:
        f.write(encrypted)

# Interface gráfica
class VaultApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Vault Seguro")
        self.geometry("400x350")
        self.attempts = 0
        self.fernet = None
        self.data = {}
        self.create_login_screen()

    def create_login_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

        tk.Label(self, text="Senha Mestra", font=("Arial", 14)).pack(pady=10)
        self.password_entry = tk.Entry(self, show="*", width=30)
        self.password_entry.pack(pady=10)

        btn_frame = tk.Frame(self)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Entrar", command=self.authenticate).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Resetar Vault", fg="red", command=self.reset_vault).grid(row=0, column=1, padx=5)


    def authenticate(self):
        password = self.password_entry.get()
        salt = load_salt()
        try:
            key = derive_key(password, salt)
            self.fernet = Fernet(key)
            self.data = load_encrypted_vault(self.fernet)
            self.show_main_screen()
        except Exception:
            self.attempts += 1
            if self.attempts >= MAX_ATTEMPTS:
                messagebox.showerror("Erro", "Muitas tentativas. Fechando.")
                self.destroy()
            else:
                messagebox.showwarning("Erro", f"Senha incorreta ({self.attempts}/{MAX_ATTEMPTS})")

    def show_main_screen(self):
        for widget in self.winfo_children():
            widget.destroy()

        tk.Label(self, text="Vault de Senhas", font=("Arial", 14)).pack(pady=10)

        self.tree = ttk.Treeview(self, columns=("App", "Senha"), show="headings")
        self.tree.heading("App", text="Aplicativo")
        self.tree.heading("Senha", text="Senha (clique p/ ver)")
        self.tree.pack(expand=True, fill="both")
        self.tree.bind("<Double-1>", self.reveal_password)

        self.load_passwords()

        frame = tk.Frame(self)
        frame.pack(pady=10)

        tk.Button(frame, text="Adicionar", command=self.add_password).grid(row=0, column=0, padx=5)
        tk.Button(frame, text="Exportar", command=self.export_encrypted).grid(row=0, column=1, padx=5)
        tk.Button(frame, text="Resetar Vault", fg="red", command=self.reset_vault).grid(row=0, column=2, padx=5)
        tk.Button(frame, text="Sair", command=self.destroy).grid(row=0, column=3, padx=5)

    def load_passwords(self):
        self.tree.delete(*self.tree.get_children())
        for app in self.data["vault"]:
            self.tree.insert("", "end", values=(app, "••••••••"))

    def reveal_password(self, event):
        selected = self.tree.focus()
        if selected:
            app = self.tree.item(selected)['values'][0]
            password = self.data["vault"].get(app)
            if password:
                messagebox.showinfo(f"{app}", f"Senha: {password}")

    def add_password(self):
        app = simpledialog.askstring("Aplicativo", "Nome do aplicativo:")
        pwd = simpledialog.askstring("Senha", "Senha do aplicativo:", show="*")
        if app and pwd:
            self.data["vault"][app] = pwd
            save_encrypted_vault(self.fernet, self.data)
            self.load_passwords()

    def export_encrypted(self):
        filename = simpledialog.askstring("Exportar", "Nome do arquivo de backup:")
        if filename:
            with open(filename, 'wb') as f:
                f.write(encrypt_data(self.fernet, self.data))
            messagebox.showinfo("Exportado", f"Backup salvo em {filename}")

    def reset_vault(self):
        confirm = simpledialog.askstring("Confirmar Reset", "Digite 'RESETAR' para apagar tudo:")
        if confirm == "RESETAR":
            try:
                os.remove(VAULT_FILE)
                os.remove(SALT_FILE)
            except FileNotFoundError:
                pass
            messagebox.showinfo("Vault Resetado", "Todos os dados foram apagados.")
            self.destroy()
        else:
            messagebox.showinfo("Cancelado", "Reset não confirmado.")

if __name__ == '__main__':
    app = VaultApp()
    app.mainloop()
