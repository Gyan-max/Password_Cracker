# Password Cracker

A Python-based password cracking application with a graphical user interface built using Tkinter. This tool is designed for educational purposes to demonstrate password security concepts.

![Password Cracker Screenshot](a.png)(b.png)

## Features

- **Brute Force Attack**: Try all possible combinations of characters up to a specified length
- **Dictionary Attack**: Test passwords from a wordlist file
- **Hash Cracking Support**: Crack MD5, SHA1, SHA256, and SHA512 hashed passwords
- **Customizable Character Sets**: Choose which character types to include (lowercase, uppercase, digits, special characters)
- **Real-time Progress Updates**: See the current password being tested and track progress
- **Responsive UI**: Modern and user-friendly interface with a sleek dark blue theme
- **Comprehensive Documentation**: Detailed user manual in both Markdown and HTML formats

## Requirements

- Python 3.6 or higher
- Tkinter (included with most Python installations)
- No additional packages required

## Quick Start

1. Run the application:
   ```
   python main.py
   ```

2. Enter the target password or hash you want to crack
3. If you're entering a hash, check the "Input is a hash" checkbox and select the appropriate hash type
4. Choose your cracking method:
   - **Brute Force**: Select character sets and maximum password length
   - **Dictionary Attack**: Select a wordlist file (.txt)
5. Click "Start Cracking" to begin the password cracking process
6. The application will display the result when found or when the process is complete

## Documentation

The application comes with comprehensive documentation:

- **User Manual**: Available in two formats:
  - `USER_MANUAL.md` - Markdown version for viewing in text editors or GitHub
  - `user_manual.html` - Styled HTML version for viewing in web browsers

To view the HTML user manual, simply open `user_manual.html` in any web browser.

## Testing Tools

The application includes a test harness to help you test different passwords and hashes:

```
python test_cracker.py
```

The test harness provides the following features:
- Test with plaintext passwords from `target_passwords.txt`
- Test with hashed passwords from `hashed_passwords.txt`
- Generate hashes from passwords for testing purposes

## Included Files

- `main.py` - The main password cracker application
- `test_cracker.py` - Test harness for testing the password cracker
- `target_passwords.txt` - Sample plaintext passwords for testing
- `test_passwords.txt` - Dictionary file for dictionary attacks
- `hashed_passwords.txt` - Sample hashed passwords for testing
- `USER_MANUAL.md` - Comprehensive user manual (Markdown format)
- `user_manual.html` - Comprehensive user manual (HTML format)

## Performance Tips

- Brute force attacks become exponentially slower as the maximum password length increases
- For passwords longer than 6 characters, a dictionary attack is recommended
- The application may become less responsive during intensive cracking operations
- Cracking complex hashes (especially SHA256 and SHA512) can be very time-consuming

## Security and Legal Notice

This application is intended for **educational purposes only**. It should be used responsibly and ethically.

- Only use this tool on systems and passwords you own or have explicit permission to test
- Unauthorized password cracking attempts may violate computer crime laws
- The developers assume no liability for misuse of this software

## Contributing

Contributions to improve the application are welcome. Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is available for educational use. Please use responsibly.
