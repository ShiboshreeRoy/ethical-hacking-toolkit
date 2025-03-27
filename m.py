import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
import threading
import queue
from tkinter.scrolledtext import ScrolledText

# ASCII character sets
ASCII_SETS = {
    "Dense (@%#*+=-:. )": "@%#*+=-:. ",
    "Medium (#*+=-:. )": "#*+=-:. ",
    "Light (*+=-:. )": "*+=-:. "
}

COLOR_THEMES = {
    "Hacker Green": "#00ff00",
    "Cyber Red": "#ff0000",
    "Ocean Blue": "#0099ff",
    "Classic White": "#ffffff"
}

class ASCIIGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("ProArt ASCII Generator")
        self.root.geometry("1000x700")
        self.style = ttk.Style()
        self.set_dark_theme()
        
        self.progress_queue = queue.Queue()
        self.current_theme = "dark"
        self.setup_ui()
        self.check_queue()

    def set_dark_theme(self):
        self.style.theme_use('clam')
        self.style.configure('.', background="#2d2d2d", foreground="#ffffff")
        self.style.configure('TFrame', background="#2d2d2d")
        self.style.configure('TLabel', background="#2d2d2d", foreground="#ffffff")
        self.style.configure('TButton', background="#404040", foreground="#ffffff")
        self.style.configure('TScale', background="#2d2d2d")
        self.style.map('TButton', background=[('active', '#505050')])

    def set_light_theme(self):
        self.style.theme_use('clam')
        self.style.configure('.', background="#ffffff", foreground="#000000")
        self.style.configure('TFrame', background="#ffffff")
        self.style.configure('TLabel', background="#ffffff", foreground="#000000")
        self.style.configure('TButton', background="#f0f0f0", foreground="#000000")
        self.style.configure('TScale', background="#ffffff")
        self.style.map('TButton', background=[('active', '#e0e0e0')])

    def setup_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Control Panel
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=5)

        ttk.Button(control_frame, text="Open Image", command=self.open_image).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Generate", command=self.start_generation).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Save", command=self.save_ascii).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Copy", command=self.copy_to_clipboard).pack(side=tk.LEFT, padx=5)

        # Settings Panel
        settings_frame = ttk.Frame(main_frame)
        settings_frame.pack(fill=tk.X, pady=5)

        ttk.Label(settings_frame, text="Width:").pack(side=tk.LEFT)
        self.width_scale = ttk.Scale(settings_frame, from_=50, to=200, value=100)
        self.width_scale.pack(side=tk.LEFT, padx=5)
        self.width_var = ttk.Label(settings_frame, text="100")
        self.width_var.pack(side=tk.LEFT)
        self.width_scale.config(command=lambda v: self.width_var.config(text=f"{float(v):.0f}"))

        ttk.Label(settings_frame, text="Style:").pack(side=tk.LEFT, padx=10)
        self.ascii_style = ttk.Combobox(settings_frame, values=list(ASCII_SETS.keys()), state='readonly')
        self.ascii_style.current(0)
        self.ascii_style.pack(side=tk.LEFT, padx=5)

        ttk.Label(settings_frame, text="Color:").pack(side=tk.LEFT, padx=10)
        self.color_style = ttk.Combobox(settings_frame, values=list(COLOR_THEMES.keys()), state='readonly')
        self.color_style.current(0)
        self.color_style.pack(side=tk.LEFT, padx=5)

        # Preview Panels
        preview_frame = ttk.Frame(main_frame)
        preview_frame.pack(fill=tk.BOTH, expand=True)

        self.img_label = ttk.Label(preview_frame)
        self.img_label.pack(side=tk.LEFT, fill=tk.Y, padx=5)

        self.ascii_text = ScrolledText(preview_frame, wrap=tk.WORD, font=('Courier', 6),
                                      bg="#1a1a1a", fg=COLOR_THEMES["Hacker Green"])
        self.ascii_text.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Status Bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN)
        self.status_bar.pack(fill=tk.X)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode='determinate')
        
        # Menu
        self.menu_bar = tk.Menu(self.root)
        self.root.config(menu=self.menu_bar)
        
        file_menu = tk.Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Open Image", command=self.open_image)
        file_menu.add_command(label="Exit", command=self.root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)
        
        theme_menu = tk.Menu(self.menu_bar, tearoff=0)
        theme_menu.add_command(label="Dark Theme", command=self.toggle_theme)
        self.menu_bar.add_cascade(label="Theme", menu=theme_menu)

    def toggle_theme(self):
        if self.current_theme == "dark":
            self.set_light_theme()
            self.current_theme = "light"
            self.ascii_text.config(bg="#ffffff", fg="#000000")
        else:
            self.set_dark_theme()
            self.current_theme = "dark"
            self.ascii_text.config(bg="#1a1a1a", fg=COLOR_THEMES["Hacker Green"])
        self.menu_bar.entryconfig(1, label="Dark Theme" if self.current_theme == "light" else "Light Theme")

    def open_image(self):
        file_path = filedialog.askopenfilename(filetypes=[
            ("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")
        ])
        if file_path:
            try:
                img = Image.open(file_path)
                img.thumbnail((200, 200))
                self.img_preview = ImageTk.PhotoImage(img)
                self.img_label.config(image=self.img_preview)
                self.image_path = file_path
                self.status_bar.config(text=f"Loaded: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load image: {str(e)}")

    def start_generation(self):
        if not hasattr(self, 'image_path'):
            messagebox.showwarning("Warning", "Please select an image first!")
            return
        
        self.progress.pack(fill=tk.X)
        self.ascii_text.delete(1.0, tk.END)
        threading.Thread(target=self.generate_ascii, daemon=True).start()

    def generate_ascii(self):
        try:
            width = int(self.width_scale.get())
            chars = ASCII_SETS[self.ascii_style.get()]
            color = COLOR_THEMES[self.color_style.get()]
            
            image = Image.open(self.image_path).convert('L')
            aspect_ratio = image.height / image.width
            new_height = int(width * aspect_ratio * 0.55)
            image = image.resize((width, new_height))
            
            pixels = image.getdata()
            ascii_str = ''.join([chars[pixel//(256//len(chars))] for pixel in pixels])
            ascii_art = '\n'.join(ascii_str[i:i+width] for i in range(0, len(ascii_str), width))
            
            self.root.after(0, self.update_ascii, ascii_art, color)
        except Exception as e:
            self.root.after(0, messagebox.showerror, "Error", str(e))
        finally:
            self.root.after(0, self.progress.pack_forget)

    def update_ascii(self, text, color):
        self.ascii_text.delete(1.0, tk.END)
        self.ascii_text.insert(tk.END, text)
        self.ascii_text.config(fg=color)
        self.status_bar.config(text="Generation Complete")

    def save_ascii(self):
        text = self.ascii_text.get(1.0, tk.END)
        if not text.strip():
            messagebox.showwarning("Warning", "No ASCII art to save!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt")]
        )
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(text)
                self.status_bar.config(text=f"Saved: {os.path.basename(file_path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed: {str(e)}")

    def copy_to_clipboard(self):
        text = self.ascii_text.get(1.0, tk.END)
        if text.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_bar.config(text="Copied to clipboard!")

    def check_queue(self):
        while not self.progress_queue.empty():
            value = self.progress_queue.get()
            self.progress['value'] = value
        self.root.after(100, self.check_queue)

if __name__ == "__main__":
    root = tk.Tk()
    app = ASCIIGenerator(root)
    root.mainloop()