import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import os
import shutil
from dotkoboshFuncs import KoboshPhrase, KoboshFile

class KoboshApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Kobosh File Encryptor/Decryptor (Tkinter)")
        self.frame = tk.Frame(root)
        self.frame.pack(padx=20, pady=20)
        self.mode = tk.StringVar(value="encrypt")
        self.kobosh_file = None
        self.decryption_key = None
        self._build_ui()

    def _build_ui(self):
        tk.Label(self.frame, text="Kobosh File Utility", font=("Arial", 16, "bold")).pack(pady=10)
        mode_frame = tk.Frame(self.frame)
        mode_frame.pack(pady=5)
        tk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode, value="encrypt").pack(side=tk.LEFT)
        tk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode, value="decrypt").pack(side=tk.LEFT)
        tk.Button(self.frame, text="Start", command=self.start).pack(pady=10)
        self.log = tk.Text(self.frame, height=15, width=70, state=tk.DISABLED)
        self.log.pack(pady=10)

    def start(self):
        self.log.config(state=tk.NORMAL)
        self.log.delete(1.0, tk.END)
        self.log.config(state=tk.DISABLED)
        if self.mode.get() == "encrypt":
            self.encrypt_flow()
        else:
            self.decrypt_flow()

    def encrypt_flow(self):
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not file_path:
            return
        intensity = simpledialog.askinteger("Intensity", "Enter encryption intensity (3-15):", minvalue=3, maxvalue=15)
        if not intensity:
            return
        tmp_dir = os.path.join(os.getcwd(), "tmp_kobosh")
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)
        kobosh = KoboshFile()
        try:
            final_path, phrase = kobosh.encrypt(file_path, tmp_dir, intensity)
            self._log(f"Encrypted file saved as: {final_path}")
            self._log(f"Key phrase to decrypt metadata:\n{phrase}")
            self.root.clipboard_clear()
            self.root.clipboard_append(phrase)
            messagebox.showinfo("Encryption Complete", f"Key phrase copied to clipboard!\n{phrase}")
        except Exception as e:
            # raise e
            self._log(f"Error: {e}")
            messagebox.showerror("Error", str(e))
        finally:
            if os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir)

    def decrypt_flow(self):
        phrase = simpledialog.askstring("Key Phrase", "Enter key phrase to decrypt metadata:")
        if not phrase:
            return
        key_bytes, err = KoboshPhrase.from_phrase(phrase)
        if err:
            self._log(f"Invalid key phrase: {err}")
            messagebox.showerror("Invalid Key Phrase", err)
            return
        kobosh_path = filedialog.askopenfilename(title="Select .kobosh file to decrypt", filetypes=[("Kobosh Files", "*.kobosh")])
        if not kobosh_path:
            return
        kobosh = KoboshFile()
        try:
            final_path = kobosh.decrypt(kobosh_path, key_bytes)
            self._log(f"Decryption complete! File saved as: {final_path}")
            messagebox.showinfo("Decryption Complete", f"File saved as: {final_path}")
        except Exception as e:
            self._log(f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def _log(self, msg):
        self.log.config(state=tk.NORMAL)
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = KoboshApp(root)
    root.mainloop()
