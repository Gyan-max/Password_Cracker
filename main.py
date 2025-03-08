import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import string
import itertools
import threading
import time
import os
import hashlib
from PIL import Image, ImageTk  # Add PIL import for image handling

# Define a new background color
BG_COLOR = "#1E3A5F"  # A darker blue color
TEXT_COLOR = "#FFFFFF"  # White text
ACCENT_COLOR = "#3498DB"  # Light blue accent
BUTTON_GREEN = "#2ECC71"  # Green for start button
BUTTON_RED = "#E74C3C"  # Red for stop button
HIGHLIGHT_COLOR = "#F1C40F"  # Yellow for results
SECONDARY_BG = "#2C4C6E"  # Slightly lighter than main background

class PasswordCracker:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Cracker")
        self.root.geometry("600x550")
        self.root.configure(bg=BG_COLOR)
        self.root.resizable(False, False)
        
        # Try to load the background image
        try:
            self.bg_image = Image.open("img.png")
            # Resize the image to fit the window
            self.bg_image = self.bg_image.resize((600, 550), Image.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(self.bg_image)
            
            # Create a canvas for the background
            self.canvas = tk.Canvas(root, width=600, height=550)
            self.canvas.pack(fill="both", expand=True)
            
            # Add the image to the canvas
            self.canvas.create_image(0, 0, image=self.bg_photo, anchor="nw")
            
            # Create a main frame with transparent background
            self.main_container = tk.Frame(self.canvas, bg=BG_COLOR)
            self.main_container.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.95, relheight=0.95)
            
            # Add a semi-transparent overlay to improve text readability
            self.overlay = tk.Frame(self.main_container, bg=BG_COLOR)
            self.overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
            self.overlay.configure(bg=BG_COLOR)
            # Make the overlay semi-transparent
            self.overlay.attributes = {'alpha': 0.85}
            
            # Use the overlay as the parent for all widgets
            self.parent_frame = self.overlay
        except Exception as e:
            print(f"Could not load background image: {e}")
            # If image loading fails, use a regular frame
            self.parent_frame = self.root
        
        self.cracking_thread = None
        self.stop_flag = False
        
        self.setup_ui()
    
    def setup_ui(self):
        # Title
        title_label = tk.Label(
            self.parent_frame,
            text="Password Cracker",
            font=("Arial", 20, "bold"),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        title_label.pack(pady=20)
        
        # Main frame
        main_frame = tk.Frame(self.parent_frame, bg=BG_COLOR)
        main_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        # Password input
        password_frame = tk.Frame(main_frame, bg=BG_COLOR)
        password_frame.pack(fill="x", pady=10)
        
        password_label = tk.Label(
            password_frame,
            text="Target Password:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        password_label.pack(side="left", padx=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(
            password_frame,
            textvariable=self.password_var,
            font=("Arial", 12),
            width=25,
            bg=SECONDARY_BG,
            fg=TEXT_COLOR,
            relief="flat",
            show="*"
        )
        self.password_entry.pack(side="left", padx=5)
        
        self.show_password_var = tk.BooleanVar()
        self.show_password_check = tk.Checkbutton(
            password_frame,
            text="Show",
            variable=self.show_password_var,
            command=self.toggle_password_visibility,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        self.show_password_check.pack(side="left", padx=5)
        
        # Hash options
        hash_frame = tk.Frame(main_frame, bg=BG_COLOR)
        hash_frame.pack(fill="x", pady=5)
        
        self.is_hashed_var = tk.BooleanVar(value=False)
        is_hashed_check = tk.Checkbutton(
            hash_frame,
            text="Input is a hash",
            variable=self.is_hashed_var,
            command=self.toggle_hash_options,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        is_hashed_check.pack(side="left", padx=5)
        
        hash_type_label = tk.Label(
            hash_frame,
            text="Hash Type:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        hash_type_label.pack(side="left", padx=5)
        
        self.hash_type_var = tk.StringVar(value="md5")
        hash_type_combo = ttk.Combobox(
            hash_frame,
            textvariable=self.hash_type_var,
            values=["md5", "sha1", "sha256", "sha512"],
            width=10,
            state="readonly"
        )
        hash_type_combo.pack(side="left", padx=5)
        
        # Options frame
        options_frame = tk.LabelFrame(
            main_frame,
            text="Cracking Options",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR,
            padx=10,
            pady=10
        )
        options_frame.pack(fill="x", pady=10)
        
        # Method selection
        method_frame = tk.Frame(options_frame, bg=BG_COLOR)
        method_frame.pack(fill="x", pady=5)
        
        method_label = tk.Label(
            method_frame,
            text="Method:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        method_label.pack(side="left", padx=5)
        
        self.method_var = tk.StringVar(value="brute_force")
        brute_force_radio = tk.Radiobutton(
            method_frame,
            text="Brute Force",
            variable=self.method_var,
            value="brute_force",
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        brute_force_radio.pack(side="left", padx=5)
        
        dictionary_radio = tk.Radiobutton(
            method_frame,
            text="Dictionary Attack",
            variable=self.method_var,
            value="dictionary",
            command=self.toggle_dictionary_options,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        dictionary_radio.pack(side="left", padx=5)
        
        # Dictionary file selection
        self.dict_frame = tk.Frame(options_frame, bg=BG_COLOR)
        
        dict_label = tk.Label(
            self.dict_frame,
            text="Dictionary File:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        dict_label.pack(side="left", padx=5)
        
        self.dict_path_var = tk.StringVar()
        dict_entry = tk.Entry(
            self.dict_frame,
            textvariable=self.dict_path_var,
            font=("Arial", 12),
            width=25,
            bg=SECONDARY_BG,
            fg=TEXT_COLOR,
            relief="flat"
        )
        dict_entry.pack(side="left", padx=5)
        
        browse_button = tk.Button(
            self.dict_frame,
            text="Browse",
            font=("Arial", 10),
            bg=ACCENT_COLOR,
            fg="white",
            relief="flat",
            command=self.browse_dictionary
        )
        browse_button.pack(side="left", padx=5)
        
        # Character set options (for brute force)
        self.charset_frame = tk.Frame(options_frame, bg=BG_COLOR)
        self.charset_frame.pack(fill="x", pady=5)
        
        charset_label = tk.Label(
            self.charset_frame,
            text="Character Set:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        charset_label.pack(side="left", padx=5)
        
        self.use_lowercase_var = tk.BooleanVar(value=True)
        lowercase_check = tk.Checkbutton(
            self.charset_frame,
            text="a-z",
            variable=self.use_lowercase_var,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        lowercase_check.pack(side="left", padx=5)
        
        self.use_uppercase_var = tk.BooleanVar(value=True)
        uppercase_check = tk.Checkbutton(
            self.charset_frame,
            text="A-Z",
            variable=self.use_uppercase_var,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        uppercase_check.pack(side="left", padx=5)
        
        self.use_digits_var = tk.BooleanVar(value=True)
        digits_check = tk.Checkbutton(
            self.charset_frame,
            text="0-9",
            variable=self.use_digits_var,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        digits_check.pack(side="left", padx=5)
        
        self.use_special_var = tk.BooleanVar(value=False)
        special_check = tk.Checkbutton(
            self.charset_frame,
            text="Special",
            variable=self.use_special_var,
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        special_check.pack(side="left", padx=5)
        
        # Max length for brute force
        length_frame = tk.Frame(options_frame, bg=BG_COLOR)
        length_frame.pack(fill="x", pady=5)
        
        length_label = tk.Label(
            length_frame,
            text="Max Length:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        length_label.pack(side="left", padx=5)
        
        self.max_length_var = tk.IntVar(value=4)
        length_spinbox = tk.Spinbox(
            length_frame,
            from_=1,
            to=8,
            textvariable=self.max_length_var,
            width=5,
            font=("Arial", 12),
            bg=SECONDARY_BG,
            fg=TEXT_COLOR,
            buttonbackground=ACCENT_COLOR
        )
        length_spinbox.pack(side="left", padx=5)
        
        warning_label = tk.Label(
            length_frame,
            text="(Higher values will be very slow)",
            font=("Arial", 10, "italic"),
            fg=BUTTON_RED,
            bg=BG_COLOR
        )
        warning_label.pack(side="left", padx=5)
        
        # Control buttons
        button_frame = tk.Frame(main_frame, bg=BG_COLOR)
        button_frame.pack(fill="x", pady=10)
        
        self.start_button = tk.Button(
            button_frame,
            text="Start Cracking",
            font=("Arial", 12, "bold"),
            bg=BUTTON_GREEN,
            fg="white",
            relief="flat",
            padx=10,
            pady=5,
            command=self.start_cracking
        )
        self.start_button.pack(side="left", padx=10, expand=True)
        
        self.stop_button = tk.Button(
            button_frame,
            text="Stop",
            font=("Arial", 12, "bold"),
            bg=BUTTON_RED,
            fg="white",
            relief="flat",
            padx=10,
            pady=5,
            command=self.stop_cracking,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=10, expand=True)
        
        # Progress and results
        progress_frame = tk.Frame(main_frame, bg=BG_COLOR)
        progress_frame.pack(fill="x", pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            orient="horizontal",
            length=550,
            mode="indeterminate",
            variable=self.progress_var
        )
        self.progress_bar.pack(fill="x", padx=10, pady=5)
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = tk.Label(
            progress_frame,
            textvariable=self.status_var,
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        status_label.pack(pady=5)
        
        self.result_var = tk.StringVar()
        result_label = tk.Label(
            progress_frame,
            textvariable=self.result_var,
            font=("Arial", 14, "bold"),
            fg=HIGHLIGHT_COLOR,
            bg=BG_COLOR
        )
        result_label.pack(pady=5)
        
        # Initialize UI state
        self.toggle_dictionary_options()
        self.toggle_hash_options()
    
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def toggle_dictionary_options(self):
        if self.method_var.get() == "dictionary":
            self.dict_frame.pack(fill="x", pady=5)
            self.charset_frame.pack_forget()
        else:
            self.dict_frame.pack_forget()
            self.charset_frame.pack(fill="x", pady=5)
    
    def toggle_hash_options(self):
        # This method is called when the "Input is a hash" checkbox is toggled
        pass
    
    def browse_dictionary(self):
        filename = filedialog.askopenfilename(
            title="Select Dictionary File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        if filename:
            self.dict_path_var.set(filename)
    
    def hash_password(self, password):
        """Hash a password using the selected algorithm"""
        hash_type = self.hash_type_var.get()
        
        if hash_type == "md5":
            return hashlib.md5(password.encode()).hexdigest()
        elif hash_type == "sha1":
            return hashlib.sha1(password.encode()).hexdigest()
        elif hash_type == "sha256":
            return hashlib.sha256(password.encode()).hexdigest()
        elif hash_type == "sha512":
            return hashlib.sha512(password.encode()).hexdigest()
        else:
            return password  # No hashing
    
    def start_cracking(self):
        target = self.password_var.get()
        if not target:
            messagebox.showerror("Error", "Please enter a target password or hash to crack")
            return
        
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.result_var.set("")
        self.stop_flag = False
        
        # Start the cracking process in a separate thread
        self.cracking_thread = threading.Thread(target=self.crack_password)
        self.cracking_thread.daemon = True
        self.cracking_thread.start()
        
        # Start progress bar
        self.progress_bar.start(10)
    
    def stop_cracking(self):
        self.stop_flag = True
        self.status_var.set("Stopping...")
        self.stop_button.config(state="disabled")
    
    def crack_password(self):
        target = self.password_var.get()
        method = self.method_var.get()
        is_hashed = self.is_hashed_var.get()
        
        start_time = time.time()
        found = False
        found_password = ""
        
        try:
            if method == "brute_force":
                max_length = self.max_length_var.get()
                charset = ""
                
                if self.use_lowercase_var.get():
                    charset += string.ascii_lowercase
                if self.use_uppercase_var.get():
                    charset += string.ascii_uppercase
                if self.use_digits_var.get():
                    charset += string.digits
                if self.use_special_var.get():
                    charset += string.punctuation
                
                if not charset:
                    self.root.after(0, lambda: messagebox.showerror("Error", "Please select at least one character set"))
                    return
                
                self.status_var.set("Brute forcing password...")
                
                # Try passwords of increasing length
                for length in range(1, max_length + 1):
                    if self.stop_flag:
                        break
                    
                    self.root.after(0, lambda l=length: self.status_var.set(f"Trying {l}-character passwords..."))
                    
                    for attempt in itertools.product(charset, repeat=length):
                        if self.stop_flag:
                            break
                        
                        password_attempt = ''.join(attempt)
                        
                        # Update status occasionally (not for every attempt as that would slow things down)
                        if sum(ord(c) for c in password_attempt) % 1000 == 0:
                            self.root.after(0, lambda p=password_attempt: self.status_var.set(f"Trying: {p}"))
                        
                        # Check if this password matches the target
                        if is_hashed:
                            hashed_attempt = self.hash_password(password_attempt)
                            if hashed_attempt == target:
                                found = True
                                found_password = password_attempt
                                break
                        else:
                            if password_attempt == target:
                                found = True
                                found_password = password_attempt
                                break
                    
                    if found:
                        break
            
            elif method == "dictionary":
                dict_path = self.dict_path_var.get()
                
                if not dict_path or not os.path.exists(dict_path):
                    self.root.after(0, lambda: messagebox.showerror("Error", "Please select a valid dictionary file"))
                    return
                
                self.status_var.set("Performing dictionary attack...")
                
                with open(dict_path, 'r', errors='ignore') as dict_file:
                    for line in dict_file:
                        if self.stop_flag:
                            break
                        
                        password_attempt = line.strip()
                        
                        # Update status occasionally
                        if sum(ord(c) for c in password_attempt) % 100 == 0:
                            self.root.after(0, lambda p=password_attempt: self.status_var.set(f"Trying: {p}"))
                        
                        # Check if this password matches the target
                        if is_hashed:
                            hashed_attempt = self.hash_password(password_attempt)
                            if hashed_attempt == target:
                                found = True
                                found_password = password_attempt
                                break
                        else:
                            if password_attempt == target:
                                found = True
                                found_password = password_attempt
                                break
        
        except Exception as e:
            self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
        
        # Calculate time taken
        elapsed_time = time.time() - start_time
        
        # Update UI with results
        if self.stop_flag:
            self.root.after(0, lambda: self.status_var.set("Stopped"))
        elif found:
            if is_hashed:
                self.root.after(0, lambda: self.status_var.set(f"Hash cracked in {elapsed_time:.2f} seconds!"))
                self.root.after(0, lambda: self.result_var.set(f"Original Password: {found_password}"))
            else:
                self.root.after(0, lambda: self.status_var.set(f"Password cracked in {elapsed_time:.2f} seconds!"))
                self.root.after(0, lambda: self.result_var.set(f"Password: {found_password}"))
        else:
            if is_hashed:
                self.root.after(0, lambda: self.status_var.set(f"Hash not cracked after {elapsed_time:.2f} seconds"))
            else:
                self.root.after(0, lambda: self.status_var.set(f"Password not found after {elapsed_time:.2f} seconds"))
        
        # Reset UI
        self.root.after(0, self.reset_ui)
    
    def reset_ui(self):
        self.progress_bar.stop()
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

if __name__ == "__main__":
    # Check if PIL is installed
    try:
        import PIL
    except ImportError:
        print("PIL (Pillow) is not installed. Installing it now...")
        import subprocess
        subprocess.check_call(["pip", "install", "pillow"])
        print("PIL (Pillow) has been installed. Restarting application...")
        import sys
        os.execv(sys.executable, [sys.executable] + sys.argv)
    
    root = tk.Tk()
    app = PasswordCracker(root)
    root.mainloop()
