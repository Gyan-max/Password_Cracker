import tkinter as tk
import csv
import time
import sys
import hashlib
from main import PasswordCracker

class TestHarness:
    def __init__(self):
        self.test_passwords = []
        self.hashed_passwords = []
        self.load_test_passwords()
        self.load_hashed_passwords()
        
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
    
    def load_hashed_passwords(self):
        """Load hashed passwords from the hashed_passwords.txt file"""
        try:
            with open('hashed_passwords.txt', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(',', 3)
                        if len(parts) == 4:
                            hash_value, original, hash_type, description = parts
                            self.hashed_passwords.append((hash_value, original, hash_type, description))
        except FileNotFoundError:
            print("Warning: hashed_passwords.txt not found.")
    
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
    
    def run_test(self, password_index=None, hash_index=None, test_type="plaintext"):
        """Run the password cracker with a specific test password or hash"""
        if password_index is None and hash_index is None:
            self.show_main_menu()
            return
        
        # Create a root window
        root = tk.Tk()
        app = PasswordCracker(root)
        
        if test_type == "plaintext" and 0 <= password_index < len(self.test_passwords):
            password, description = self.test_passwords[password_index]
            print(f"\nTesting password: '{password}' ({description})")
            print("Starting the Password Cracker application...")
            print("Please enter this password in the 'Target Password' field.")
            print("Then select your cracking method and start the process.")
            
            # Set the password in the entry field
            app.password_var.set(password)
            app.is_hashed_var.set(False)
            
        elif test_type == "hash" and 0 <= hash_index < len(self.hashed_passwords):
            hash_value, original, hash_type, description = self.hashed_passwords[hash_index]
            print(f"\nTesting hash: '{hash_value}'")
            print(f"Original password: '{original}'")
            print(f"Hash type: {hash_type}")
            print(f"Description: {description}")
            print("\nStarting the Password Cracker application...")
            print("The hash has been entered in the 'Target Password' field.")
            print("Make sure 'Input is a hash' is checked and the correct hash type is selected.")
            print("Then select your cracking method and start the process.")
            
            # Set the hash in the entry field and configure hash options
            app.password_var.set(hash_value)
            app.is_hashed_var.set(True)
            app.hash_type_var.set(hash_type)
            
        else:
            print("Invalid selection.")
            root.destroy()
            return
        
        # Run the application
        root.mainloop()
    
    def generate_hash(self):
        """Generate a hash from a password for testing"""
        password = input("\nEnter the password to hash: ")
        if not password:
            print("No password entered.")
            return
            
        print("\nSelect hash type:")
        print("1. MD5")
        print("2. SHA1")
        print("3. SHA256")
        print("4. SHA512")
        
        try:
            choice = int(input("\nEnter choice (1-4): "))
            hash_types = ["md5", "sha1", "sha256", "sha512"]
            if 1 <= choice <= 4:
                hash_type = hash_types[choice-1]
                hashed = self.hash_password(password, hash_type)
                print(f"\nOriginal password: {password}")
                print(f"Hash type: {hash_type}")
                print(f"Hashed value: {hashed}")
                print(f"\nFor hashed_passwords.txt:")
                print(f"{hashed},{password},{hash_type},User generated {hash_type} hash of '{password}'")
            else:
                print("Invalid selection.")
        except ValueError:
            print("Please enter a valid number.")
    
    def show_password_selection(self):
        """Display available test passwords and let user select one"""
        if not self.test_passwords:
            print("\nNo test passwords available. Please create target_passwords.txt file.")
            self.show_main_menu()
            return
            
        print("\n=== Available Test Passwords ===")
        print("Select a password to test:")
        
        for i, (password, description) in enumerate(self.test_passwords):
            print(f"{i+1}. {password} - {description}")
        
        print("\n0. Back to main menu")
        
        try:
            choice = int(input("\nEnter number (0-{}): ".format(len(self.test_passwords))))
            if choice == 0:
                self.show_main_menu()
            elif 1 <= choice <= len(self.test_passwords):
                self.run_test(password_index=choice-1, test_type="plaintext")
            else:
                print("Invalid selection.")
                self.show_password_selection()
        except ValueError:
            print("Please enter a valid number.")
            self.show_password_selection()
    
    def show_hash_selection(self):
        """Display available hashed passwords and let user select one"""
        if not self.hashed_passwords:
            print("\nNo hashed passwords available. Please create hashed_passwords.txt file.")
            self.show_main_menu()
            return
            
        print("\n=== Available Hashed Passwords ===")
        print("Select a hash to test:")
        
        for i, (hash_value, original, hash_type, description) in enumerate(self.hashed_passwords):
            print(f"{i+1}. {hash_type}: {hash_value[:20]}... - {description}")
        
        print("\n0. Back to main menu")
        
        try:
            choice = int(input("\nEnter number (0-{}): ".format(len(self.hashed_passwords))))
            if choice == 0:
                self.show_main_menu()
            elif 1 <= choice <= len(self.hashed_passwords):
                self.run_test(hash_index=choice-1, test_type="hash")
            else:
                print("Invalid selection.")
                self.show_hash_selection()
        except ValueError:
            print("Please enter a valid number.")
            self.show_hash_selection()
    
    def show_main_menu(self):
        """Display the main menu"""
        print("\n=== Password Cracker Test Harness ===")
        print("1. Test with plaintext password")
        print("2. Test with hashed password")
        print("3. Generate hash from password")
        print("4. Exit")
        
        try:
            choice = int(input("\nEnter choice (1-4): "))
            if choice == 1:
                self.show_password_selection()
            elif choice == 2:
                self.show_hash_selection()
            elif choice == 3:
                self.generate_hash()
                self.show_main_menu()
            elif choice == 4:
                print("Exiting...")
                sys.exit(0)
            else:
                print("Invalid selection.")
                self.show_main_menu()
        except ValueError:
            print("Please enter a valid number.")
            self.show_main_menu()

if __name__ == "__main__":
    print("=== Password Cracker Test Harness ===")
    print("This tool helps you test the Password Cracker with different passwords and hashes.")
    
    tester = TestHarness()
    tester.show_main_menu() 