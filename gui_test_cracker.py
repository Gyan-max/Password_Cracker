import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import csv
import time
import sys
import hashlib
import os
from main import PasswordCracker

# Define colors to match the main application
BG_COLOR = "#1E3A5F"  # A darker blue color
TEXT_COLOR = "#FFFFFF"  # White text
ACCENT_COLOR = "#3498DB"  # Light blue accent
BUTTON_GREEN = "#2ECC71"  # Green for start button
BUTTON_RED = "#E74C3C"  # Red for stop button
HIGHLIGHT_COLOR = "#F1C40F"  # Yellow for results
SECONDARY_BG = "#2C4C6E"  # Slightly lighter than main background

class TestCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Cracker - Test Harness")
        self.root.geometry("800x600")
        self.root.configure(bg=BG_COLOR)
        self.root.resizable(True, True)
        
        # Try to load the background image
        try:
            from PIL import Image, ImageTk
            self.bg_image = Image.open("img.png")
            # Resize the image to fit the window
            self.bg_image = self.bg_image.resize((800, 600), Image.LANCZOS)
            self.bg_photo = ImageTk.PhotoImage(self.bg_image)
            
            # Create a canvas for the background
            self.canvas = tk.Canvas(root, width=800, height=600)
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
        
        # Initialize data
        self.test_passwords = []
        self.hashed_passwords = []
        self.load_test_passwords()
        self.load_hashed_passwords()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.parent_frame)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.plaintext_tab = tk.Frame(self.notebook, bg=BG_COLOR)
        self.hash_tab = tk.Frame(self.notebook, bg=BG_COLOR)
        self.generate_tab = tk.Frame(self.notebook, bg=BG_COLOR)
        
        self.notebook.add(self.plaintext_tab, text="Plaintext Passwords")
        self.notebook.add(self.hash_tab, text="Hashed Passwords")
        self.notebook.add(self.generate_tab, text="Generate Hash")
        
        # Set up each tab
        self.setup_plaintext_tab()
        self.setup_hash_tab()
        self.setup_generate_tab()
    
    def load_test_passwords(self):
        """Load test passwords from the target_passwords.txt file"""
        try:
            with open('target_passwords.txt', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(',', 1)
                        if len(parts) == 2:
                            password, description = parts
                            self.test_passwords.append((password, description))
        except FileNotFoundError:
            print("Warning: target_passwords.txt not found.")
            
        # Also try to load from easy_hashes.txt if it exists
        try:
            with open('easy_hashes.txt', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(',', 3)
                        if len(parts) == 4:
                            _, password, _, _ = parts
                            if (password, "From easy_hashes.txt") not in self.test_passwords:
                                self.test_passwords.append((password, "From easy_hashes.txt"))
        except FileNotFoundError:
            pass
    
    def load_hashed_passwords(self):
        """Load hashed passwords from the hashed_passwords.txt file"""
        files_to_try = ['hashed_passwords.txt', 'easy_hashes.txt']
        
        for file_name in files_to_try:
            try:
                with open(file_name, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split(',', 3)
                            if len(parts) == 4:
                                hash_value, original, hash_type, description = parts
                                self.hashed_passwords.append((hash_value, original, hash_type, description))
            except FileNotFoundError:
                print(f"Warning: {file_name} not found.")
    
    def setup_plaintext_tab(self):
        """Set up the plaintext passwords tab"""
        # Title
        title_label = tk.Label(
            self.plaintext_tab,
            text="Test with Plaintext Passwords",
            font=("Arial", 16, "bold"),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        title_label.pack(pady=10)
        
        # Create a frame for the password list
        list_frame = tk.Frame(self.plaintext_tab, bg=BG_COLOR)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create a scrolled text widget to display passwords
        self.password_list = scrolledtext.ScrolledText(
            list_frame,
            width=70,
            height=15,
            bg=SECONDARY_BG,
            fg=TEXT_COLOR,
            font=("Courier New", 10)
        )
        self.password_list.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Populate the password list
        self.password_list.insert(tk.END, "Available Test Passwords:\n")
        self.password_list.insert(tk.END, "=" * 70 + "\n\n")
        
        for i, (password, description) in enumerate(self.test_passwords):
            self.password_list.insert(tk.END, f"{i+1}. {password} - {description}\n")
        
        # Create a frame for selection
        selection_frame = tk.Frame(self.plaintext_tab, bg=BG_COLOR)
        selection_frame.pack(fill="x", padx=10, pady=10)
        
        # Add a label and entry for password selection
        select_label = tk.Label(
            selection_frame,
            text="Select Password #:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        select_label.pack(side="left", padx=5)
        
        self.password_index_var = tk.StringVar()
        password_entry = tk.Entry(
            selection_frame,
            textvariable=self.password_index_var,
            font=("Arial", 12),
            width=5,
            bg=SECONDARY_BG,
            fg=TEXT_COLOR
        )
        password_entry.pack(side="left", padx=5)
        
        # Add a test button
        test_button = tk.Button(
            selection_frame,
            text="Test Password",
            font=("Arial", 12, "bold"),
            bg=BUTTON_GREEN,
            fg="white",
            relief="flat",
            padx=10,
            pady=5,
            command=self.test_plaintext_password
        )
        test_button.pack(side="left", padx=20)
    
    def setup_hash_tab(self):
        """Set up the hashed passwords tab"""
        # Title
        title_label = tk.Label(
            self.hash_tab,
            text="Test with Hashed Passwords",
            font=("Arial", 16, "bold"),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        title_label.pack(pady=10)
        
        # Create a frame for the hash list
        list_frame = tk.Frame(self.hash_tab, bg=BG_COLOR)
        list_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create a scrolled text widget to display hashes
        self.hash_list = scrolledtext.ScrolledText(
            list_frame,
            width=70,
            height=15,
            bg=SECONDARY_BG,
            fg=TEXT_COLOR,
            font=("Courier New", 10)
        )
        self.hash_list.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Populate the hash list
        self.hash_list.insert(tk.END, "Available Hashed Passwords:\n")
        self.hash_list.insert(tk.END, "=" * 70 + "\n\n")
        
        for i, (hash_value, original, hash_type, description) in enumerate(self.hashed_passwords):
            # Truncate long hashes for display
            display_hash = hash_value[:20] + "..." if len(hash_value) > 23 else hash_value
            self.hash_list.insert(tk.END, f"{i+1}. [{hash_type}] {display_hash} - {description}\n")
        
        # Create a frame for selection
        selection_frame = tk.Frame(self.hash_tab, bg=BG_COLOR)
        selection_frame.pack(fill="x", padx=10, pady=10)
        
        # Add a label and entry for hash selection
        select_label = tk.Label(
            selection_frame,
            text="Select Hash #:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        select_label.pack(side="left", padx=5)
        
        self.hash_index_var = tk.StringVar()
        hash_entry = tk.Entry(
            selection_frame,
            textvariable=self.hash_index_var,
            font=("Arial", 12),
            width=5,
            bg=SECONDARY_BG,
            fg=TEXT_COLOR
        )
        hash_entry.pack(side="left", padx=5)
        
        # Add a test button
        test_button = tk.Button(
            selection_frame,
            text="Test Hash",
            font=("Arial", 12, "bold"),
            bg=BUTTON_GREEN,
            fg="white",
            relief="flat",
            padx=10,
            pady=5,
            command=self.test_hash
        )
        test_button.pack(side="left", padx=20)
    
    def setup_generate_tab(self):
        """Set up the generate hash tab"""
        # Title
        title_label = tk.Label(
            self.generate_tab,
            text="Generate Hash from Password",
            font=("Arial", 16, "bold"),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        title_label.pack(pady=10)
        
        # Create a frame for password input
        input_frame = tk.Frame(self.generate_tab, bg=BG_COLOR)
        input_frame.pack(fill="x", padx=10, pady=10)
        
        # Add a label and entry for password input
        password_label = tk.Label(
            input_frame,
            text="Password:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        password_label.pack(side="left", padx=5)
        
        self.password_var = tk.StringVar()
        password_entry = tk.Entry(
            input_frame,
            textvariable=self.password_var,
            font=("Arial", 12),
            width=30,
            bg=SECONDARY_BG,
            fg=TEXT_COLOR
        )
        password_entry.pack(side="left", padx=5)
        
        # Create a frame for hash type selection
        hash_type_frame = tk.Frame(self.generate_tab, bg=BG_COLOR)
        hash_type_frame.pack(fill="x", padx=10, pady=10)
        
        # Add radio buttons for hash type
        hash_type_label = tk.Label(
            hash_type_frame,
            text="Hash Type:",
            font=("Arial", 12),
            fg=TEXT_COLOR,
            bg=BG_COLOR
        )
        hash_type_label.pack(side="left", padx=5)
        
        self.hash_type_var = tk.StringVar(value="md5")
        
        md5_radio = tk.Radiobutton(
            hash_type_frame,
            text="MD5",
            variable=self.hash_type_var,
            value="md5",
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        md5_radio.pack(side="left", padx=5)
        
        sha1_radio = tk.Radiobutton(
            hash_type_frame,
            text="SHA1",
            variable=self.hash_type_var,
            value="sha1",
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        sha1_radio.pack(side="left", padx=5)
        
        sha256_radio = tk.Radiobutton(
            hash_type_frame,
            text="SHA256",
            variable=self.hash_type_var,
            value="sha256",
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        sha256_radio.pack(side="left", padx=5)
        
        sha512_radio = tk.Radiobutton(
            hash_type_frame,
            text="SHA512",
            variable=self.hash_type_var,
            value="sha512",
            bg=BG_COLOR,
            fg=TEXT_COLOR,
            selectcolor=SECONDARY_BG,
            activebackground=BG_COLOR,
            activeforeground=TEXT_COLOR
        )
        sha512_radio.pack(side="left", padx=5)
        
        # Add a generate button
        button_frame = tk.Frame(self.generate_tab, bg=BG_COLOR)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        generate_button = tk.Button(
            button_frame,
            text="Generate Hash",
            font=("Arial", 12, "bold"),
            bg=BUTTON_GREEN,
            fg="white",
            relief="flat",
            padx=10,
            pady=5,
            command=self.generate_hash
        )
        generate_button.pack(padx=20)
        
        # Create a frame for results
        result_frame = tk.Frame(self.generate_tab, bg=BG_COLOR)
        result_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add a scrolled text widget for results
        self.result_text = scrolledtext.ScrolledText(
            result_frame,
            width=70,
            height=10,
            bg=SECONDARY_BG,
            fg=TEXT_COLOR,
            font=("Courier New", 10)
        )
        self.result_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a copy button
        copy_button = tk.Button(
            result_frame,
            text="Copy to Clipboard",
            font=("Arial", 10),
            bg=ACCENT_COLOR,
            fg="white",
            relief="flat",
            command=self.copy_to_clipboard
        )
        copy_button.pack(pady=5)
    
    def hash_password(self, password, hash_type):
        """Hash a password using the specified algorithm"""
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
    
    def test_plaintext_password(self):
        """Test with a plaintext password"""
        try:
            index = int(self.password_index_var.get()) - 1
            if 0 <= index < len(self.test_passwords):
                password, description = self.test_passwords[index]
                
                # Create a new window for the password cracker
                cracker_window = tk.Toplevel(self.root)
                cracker_window.title("Password Cracker - Testing Plaintext")
                
                # Display information about the test
                info_frame = tk.Frame(cracker_window, bg=BG_COLOR)
                info_frame.pack(fill="x", padx=10, pady=10)
                
                info_text = f"Testing password: '{password}'\nDescription: {description}"
                info_label = tk.Label(
                    info_frame,
                    text=info_text,
                    font=("Arial", 12),
                    fg=TEXT_COLOR,
                    bg=BG_COLOR,
                    justify="left"
                )
                info_label.pack(pady=10)
                
                # Create the password cracker instance
                app = PasswordCracker(cracker_window)
                app.password_var.set(password)
                app.is_hashed_var.set(False)
            else:
                messagebox.showerror("Error", "Invalid password index")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number")
    
    def test_hash(self):
        """Test with a hashed password"""
        try:
            index = int(self.hash_index_var.get()) - 1
            if 0 <= index < len(self.hashed_passwords):
                hash_value, original, hash_type, description = self.hashed_passwords[index]
                
                # Create a new window for the password cracker
                cracker_window = tk.Toplevel(self.root)
                cracker_window.title("Password Cracker - Testing Hash")
                
                # Display information about the test
                info_frame = tk.Frame(cracker_window, bg=BG_COLOR)
                info_frame.pack(fill="x", padx=10, pady=10)
                
                info_text = f"Testing hash: '{hash_value}'\nOriginal password: '{original}'\nHash type: {hash_type}\nDescription: {description}"
                info_label = tk.Label(
                    info_frame,
                    text=info_text,
                    font=("Arial", 12),
                    fg=TEXT_COLOR,
                    bg=BG_COLOR,
                    justify="left"
                )
                info_label.pack(pady=10)
                
                # Create the password cracker instance
                app = PasswordCracker(cracker_window)
                app.password_var.set(hash_value)
                app.is_hashed_var.set(True)
                app.hash_type_var.set(hash_type)
            else:
                messagebox.showerror("Error", "Invalid hash index")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number")
    
    def generate_hash(self):
        """Generate a hash from a password"""
        password = self.password_var.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        hash_type = self.hash_type_var.get()
        hashed = self.hash_password(password, hash_type)
        
        # Clear previous results
        self.result_text.delete(1.0, tk.END)
        
        # Display results
        self.result_text.insert(tk.END, f"Original password: {password}\n")
        self.result_text.insert(tk.END, f"Hash type: {hash_type}\n")
        self.result_text.insert(tk.END, f"Hashed value: {hashed}\n\n")
        self.result_text.insert(tk.END, f"For hashed_passwords.txt:\n")
        self.result_text.insert(tk.END, f"{hashed},{password},{hash_type},User generated {hash_type} hash of '{password}'\n")
    
    def copy_to_clipboard(self):
        """Copy the hash result to clipboard"""
        selected_text = self.result_text.get(1.0, tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(selected_text)
        messagebox.showinfo("Copied", "Hash information copied to clipboard")

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
    app = TestCrackerGUI(root)
    root.mainloop() 