# Password Cracker - User Manual

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Interface Overview](#interface-overview)
5. [Cracking Methods](#cracking-methods)
   - [Brute Force Attack](#brute-force-attack)
   - [Dictionary Attack](#dictionary-attack)
6. [Working with Hashed Passwords](#working-with-hashed-passwords)
7. [Testing Tools](#testing-tools)
8. [Performance Tips](#performance-tips)
9. [Troubleshooting](#troubleshooting)
10. [Security and Legal Considerations](#security-and-legal-considerations)

## Introduction

Password Cracker is a Python-based application with a graphical user interface that allows you to test the strength of passwords using different cracking methods. This tool is designed for educational purposes to help understand password security concepts and demonstrate why strong passwords are important.

The application supports:
- Brute force attacks (trying all possible character combinations)
- Dictionary attacks (using wordlists)
- Cracking both plaintext and hashed passwords (MD5, SHA1, SHA256, SHA512)

## Installation

### Requirements
- Python 3.6 or higher
- Tkinter (included with most Python installations)

### Setup
1. Clone or download the repository to your local machine
2. Navigate to the project directory
3. No additional packages are required as the application uses only standard Python libraries

## Getting Started

To launch the application:

```
python main.py
```

For testing with sample passwords and hashes:

```
python test_cracker.py
```

## Interface Overview

The Password Cracker interface is divided into several sections:

![Password Cracker Interface](img.png)

1. **Target Password Input**
   - Enter the password or hash you want to crack
   - Toggle visibility with the "Show" checkbox

2. **Hash Options**
   - Check "Input is a hash" if you're entering a hash instead of plaintext
   - Select the hash type (MD5, SHA1, SHA256, SHA512)

3. **Cracking Options**
   - Choose between Brute Force and Dictionary Attack methods
   - Configure method-specific settings

4. **Control Buttons**
   - Start Cracking: Begin the password cracking process
   - Stop: Halt an ongoing cracking process

5. **Progress and Results**
   - Progress bar shows activity
   - Status messages display current operation
   - Results appear when a password is found

## Cracking Methods

### Brute Force Attack

The brute force method tries all possible combinations of characters until it finds the correct password.

#### Configuration Options:
- **Character Set**: Select which types of characters to include
  - a-z: Lowercase letters
  - A-Z: Uppercase letters
  - 0-9: Digits
  - Special: Punctuation and special characters
- **Max Length**: The maximum password length to try (1-8)

#### Best Used For:
- Short passwords (1-4 characters)
- When you have no idea what the password might be
- Testing password complexity

#### Limitations:
- Exponentially slower as password length increases
- Impractical for passwords longer than 6 characters

### Dictionary Attack

The dictionary attack tries passwords from a wordlist file.

#### Configuration Options:
- **Dictionary File**: Select a text file containing potential passwords (one per line)

#### Best Used For:
- Common passwords
- Longer passwords that might be dictionary words
- When you suspect the password follows common patterns

#### Limitations:
- Limited to passwords in the dictionary file
- Won't find complex passwords that aren't in the wordlist

## Working with Hashed Passwords

Password Cracker can attempt to crack password hashes in addition to plaintext passwords.

### Supported Hash Types:
- MD5
- SHA1
- SHA256
- SHA512

### How to Crack a Hash:
1. Enter the hash in the "Target Password" field
2. Check the "Input is a hash" checkbox
3. Select the correct hash type
4. Choose your cracking method
5. Click "Start Cracking"

### Notes on Hash Cracking:
- The application will hash each password attempt using the selected algorithm
- Cracking hashes is more CPU-intensive than plaintext passwords
- SHA256 and SHA512 hashes take significantly longer to crack than MD5 or SHA1

## Testing Tools

The application includes a test harness (`test_cracker.py`) to help you test different passwords and hashes.

### Features:
- Test with plaintext passwords from `target_passwords.txt`
- Test with hashed passwords from `hashed_passwords.txt`
- Generate hashes from passwords for testing purposes

### Using the Test Harness:
1. Run `python test_cracker.py`
2. Select from the main menu:
   - Test with plaintext password
   - Test with hashed password
   - Generate hash from password

## Performance Tips

1. **For Brute Force Attacks:**
   - Limit the character sets to only what's necessary
   - Start with a small max length and increase gradually
   - Use dictionary attack for passwords longer than 4 characters

2. **For Dictionary Attacks:**
   - Use smaller, targeted dictionaries when possible
   - Organize dictionaries by theme or complexity

3. **For Hash Cracking:**
   - MD5 is the fastest to crack, followed by SHA1, SHA256, and SHA512
   - Consider using dictionary attack for hashes

4. **General Tips:**
   - The application may become less responsive during intensive cracking operations
   - For very complex passwords, be prepared to let the application run for extended periods
   - Use the Stop button if the process is taking too long

## Troubleshooting

### Common Issues:

1. **Application Freezes**
   - The UI may become less responsive during intensive cracking operations
   - This is normal and the application is still working
   - For very complex passwords, consider using the Stop button and trying a different approach

2. **Dictionary Attack Not Working**
   - Ensure the dictionary file exists and is readable
   - Check that each password is on a separate line
   - Verify the file encoding is compatible (UTF-8 recommended)

3. **Hash Not Being Cracked**
   - Verify you've selected the correct hash type
   - Ensure the hash is entered correctly (no extra spaces)
   - Try a different cracking method or dictionary

4. **Slow Performance**
   - Reduce the character set for brute force attacks
   - Use a smaller dictionary file
   - Limit the maximum password length
   - Consider that some hashes (SHA256, SHA512) are inherently slower to compute

## Security and Legal Considerations

This Password Cracker application is intended for **educational purposes only**. It should be used responsibly and ethically.

### Legal Warning:
- Only use this tool on systems and passwords you own or have explicit permission to test
- Unauthorized password cracking attempts may violate computer crime laws
- The developers assume no liability for misuse of this software

### Security Best Practices:
- Use this tool to test the strength of your own passwords
- Create strong passwords that would be difficult to crack with this tool
- Use different passwords for different services
- Consider using a password manager for generating and storing complex passwords

---

*This user manual is provided for educational purposes. The Password Cracker application is a demonstration tool and should be used responsibly.* 