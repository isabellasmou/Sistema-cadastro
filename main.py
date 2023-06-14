import tkinter as tk
from tkinter import messagebox
import sqlite3
import re
import hashlib

def limpar_campos():
    entrada_usuario.delete(0, tk.END)
    entrada_senha.delete(0, tk.END)

def verificar_senha(senha):
    
    if len(senha) < 8:
        return False

    if not re.search(r'[a-zA-Z]', senha) or \
       not re.search(r'\d', senha) or \
       not re.search(r'[!@#$%^&*()-_=+{}[\]|;:,<.>]', senha):
        return False

    return True

def cadastrar():
    usuario = entrada_usuario.get()
    senha = entrada_senha.get()

    if usuario == '' or senha == '':
        messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
        return

    conn = sqlite3.connect('usuarios.db')
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios
                      (usuario TEXT PRIMARY KEY, senha TEXT)''')

    cursor.execute('SELECT usuario FROM usuarios WHERE usuario = ?', (usuario,))
    result = cursor.fetchone()
    if result is not None:
        messagebox.showerror("Erro", "Usuário já cadastrado.")
        conn.close()
        return

    if not verificar_senha(senha):
        messagebox.showerror("Erro", "A senha deve ter no mínimo oito caracteres, contendo letras, números e símbolos especiais.")
        conn.close()
        return

    senha_hash = hashlib.sha256(senha.encode()).hexdigest()

    cursor.execute('INSERT INTO usuarios VALUES (?, ?)', (usuario, senha_hash))
    conn.commit()

    messagebox.showinfo("Sucesso", "Cadastro realizado com sucesso.")

    conn.close()
    limpar_campos()

def fazer_login():
    usuario = entrada_usuario.get()
    senha = entrada_senha.get()

    if usuario == '' or senha == '':
        messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
        return

    try:
        conn = sqlite3.connect('usuarios.db')
        cursor = conn.cursor()

        cursor.execute('SELECT senha FROM usuarios WHERE usuario = ?', (usuario,))
        result = cursor.fetchone()

        if result is None:
            messagebox.showerror("Erro", "Usuário não encontrado.")
        else:
            
            senha_hash = hashlib.sha256(senha.encode()).hexdigest()

            if senha_hash == result[0]:
                messagebox.showinfo("Sucesso", "Login realizado com sucesso.")
            else:
                messagebox.showerror("Erro", "Senha incorreta.")

    except sqlite3.Error as e:
        messagebox.showerror("Erro", f"Ocorreu um erro no banco de dados: {str(e)}")

    finally:
        conn.close()

root = tk.Tk()
root.title("Página Inicial")
root.geometry('400x300+550+200')
root.resizable(False, False)
root.configure(bg="#000000")

entrada_estilo = {'width': 20, 'font': ('Arial', 12)}

frame_cadastro = tk.Frame(root, bg="#000000")
frame_cadastro.pack(pady=20)

lbl_usuario = tk.Label(frame_cadastro, text="Usuário:", bg="#000000", fg="#ffffff", font=('Arial', 12))
lbl_usuario.grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
entrada_usuario = tk.Entry(frame_cadastro, **entrada_estilo)
entrada_usuario.grid(row=0, column=1, padx=5, pady=5)

lbl_senha = tk.Label(frame_cadastro, text="Senha:", bg="#000000", fg="#ffffff", font=('Arial', 12))
lbl_senha.grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
entrada_senha = tk.Entry(frame_cadastro, show="*", **entrada_estilo)
entrada_senha.grid(row=1, column=1, padx=5, pady=5)

frame_botoes = tk.Frame(root, bg="#000000")
frame_botoes.pack(pady=10)

btn_cadastrar = tk.Button(frame_botoes, text="Cadastrar", command=cadastrar, bg="#ffffff", fg="#000000", font=('Arial', 12))
btn_cadastrar.pack(side=tk.LEFT, padx=5, pady=10)

btn_login = tk.Button(frame_botoes, text="Login", command=fazer_login, bg="#ffffff", fg="#000000", font=('Arial', 12))
btn_login.pack(side=tk.LEFT, padx=5, pady=10)

root.update_idletasks()
frame_cadastro.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
frame_botoes.place(relx=0.5, rely=0.7, anchor=tk.CENTER)

root.mainloop()
