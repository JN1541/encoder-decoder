import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import base64
import urllib.parse
import codecs

# ---------- Logic ---------- #

def encode_main():
    raw = input_main.get("1.0", tk.END).strip()
    method = encoding_type.get()

    try:
        if method == "Base64":
            result = base64.b64encode(raw.encode()).decode()
        elif method == "Hex":
            result = raw.encode().hex()
        elif method == "ASCII":
            result = ' '.join(str(ord(c)) for c in raw)
        elif method == "Binary":
            result = ' '.join(format(ord(c), '08b') for c in raw)
        elif method == "ROT13":
            result = codecs.encode(raw, 'rot_13')
        elif method == "URL":
            result = urllib.parse.quote(raw)
        else:
            raise ValueError("Unknown encoding type.")
        output_main.delete("1.0", tk.END)
        output_main.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Encoding Error", str(e))

def decode_main():
    raw = input_main.get("1.0", tk.END).strip()
    method = encoding_type.get()

    try:
        if method == "Base64":
            result = base64.b64decode(raw.encode()).decode()
        elif method == "Hex":
            result = bytes.fromhex(raw).decode()
        elif method == "ASCII":
            result = ''.join(chr(int(num)) for num in raw.split())
        elif method == "Binary":
            result = ''.join(chr(int(b, 2)) for b in raw.split())
        elif method == "ROT13":
            result = codecs.decode(raw, 'rot_13')
        elif method == "URL":
            result = urllib.parse.unquote(raw)
        else:
            raise ValueError("Unknown decoding type.")
        output_main.delete("1.0", tk.END)
        output_main.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Decoding Error", str(e))

def clear_main():
    input_main.delete("1.0", tk.END)
    output_main.delete("1.0", tk.END)

# --- Binary View Logic --- #

def binary_encode():
    raw = input_bin.get("1.0", tk.END).strip()
    if not raw:
        messagebox.showwarning("Empty Input", "Please enter text to convert.")
        return
    binary = ' '.join(format(ord(c), '08b') for c in raw)
    output_bin.delete("1.0", tk.END)
    output_bin.insert(tk.END, binary)

def binary_decode():
    raw = input_bin.get("1.0", tk.END).strip()
    try:
        text = ''.join(chr(int(b, 2)) for b in raw.split())
        output_bin.delete("1.0", tk.END)
        output_bin.insert(tk.END, text)
    except Exception as e:
        messagebox.showerror("Decode Error", f"Invalid binary input.\n{e}")

def clear_binary():
    input_bin.delete("1.0", tk.END)
    output_bin.delete("1.0", tk.END)

# ---------- GUI ---------- #

root = tk.Tk()
root.title("Multi-Encoding & Binary Viewer")
root.geometry("700x550")
root.configure(bg="#202020")
FONT = ("Segoe UI", 11)

notebook = ttk.Notebook(root)
notebook.pack(expand=1, fill="both")

# ---------- Style ---------- #
style = ttk.Style()
style.theme_use("default")
style.configure("TNotebook", background="#202020")
style.configure("TNotebook.Tab", background="#444", foreground="#fff", padding=6)
style.map("TNotebook.Tab", background=[("selected", "#333")])

BTN_STYLE = {"font": FONT, "bg": "#444", "fg": "#fff", "activebackground": "#666", "activeforeground": "#fff", "bd": 0, "padx": 10, "pady": 5}

# ---------- Tab 1: Main ---------- #
frame_main = tk.Frame(notebook, bg="#202020")
notebook.add(frame_main, text="Multi-Encode")

tk.Label(frame_main, text="Choose Encoding:", bg="#202020", fg="#fff", font=("Segoe UI", 12, "bold")).pack(pady=(10, 2))
encoding_type = ttk.Combobox(frame_main, values=["Base64", "Hex", "ASCII", "Binary", "ROT13", "URL"])
encoding_type.set("Base64")
encoding_type.pack(pady=5)

tk.Label(frame_main, text="Input:", bg="#202020", fg="#fff", font=("Segoe UI", 12, "bold")).pack()
input_main = scrolledtext.ScrolledText(frame_main, width=80, height=6, font=FONT)
input_main.pack(pady=5)

main_btn_frame = tk.Frame(frame_main, bg="#202020")
main_btn_frame.pack(pady=10)
tk.Button(main_btn_frame, text="Encode", command=encode_main, **BTN_STYLE).grid(row=0, column=0, padx=5)
tk.Button(main_btn_frame, text="Decode", command=decode_main, **BTN_STYLE).grid(row=0, column=1, padx=5)
tk.Button(main_btn_frame, text="Clear", command=clear_main, **BTN_STYLE).grid(row=0, column=2, padx=5)

tk.Label(frame_main, text="Output:", bg="#202020", fg="#fff", font=("Segoe UI", 12, "bold")).pack()
output_main = scrolledtext.ScrolledText(frame_main, width=80, height=6, font=FONT, bg="#1e1e1e", fg="#00ffcc")
output_main.pack(pady=5)

# ---------- Tab 2: Binary ---------- #
frame_bin = tk.Frame(notebook, bg="#202020")
notebook.add(frame_bin, text="Binary View")

tk.Label(frame_bin, text="Enter Text or Binary:", bg="#202020", fg="#fff", font=("Segoe UI", 12, "bold")).pack(pady=(10, 2))
input_bin = scrolledtext.ScrolledText(frame_bin, width=80, height=6, font=FONT)
input_bin.pack(pady=5)

bin_btn_frame = tk.Frame(frame_bin, bg="#202020")
bin_btn_frame.pack(pady=10)
tk.Button(bin_btn_frame, text="Text → Binary", command=binary_encode, **BTN_STYLE).grid(row=0, column=0, padx=5)
tk.Button(bin_btn_frame, text="Binary → Text", command=binary_decode, **BTN_STYLE).grid(row=0, column=1, padx=5)
tk.Button(bin_btn_frame, text="Clear", command=clear_binary, **BTN_STYLE).grid(row=0, column=2, padx=5)

tk.Label(frame_bin, text="Result:", bg="#202020", fg="#fff", font=("Segoe UI", 12, "bold")).pack()
output_bin = scrolledtext.ScrolledText(frame_bin, width=80, height=6, font=FONT, bg="#1e1e1e", fg="#00ffcc")
output_bin.pack(pady=5)

# ---------- Run ---------- #
root.mainloop()

