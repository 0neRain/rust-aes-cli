# 🔐 Rust CLI Encryption/Decryption Tool

## Overview

A simple, fast, and secure **command-line tool** for encrypting and decrypting files and directories using **AES-GCM encryption**.

## Features

- **AES-GCM encryption** for strong security.
- Encrypt **both files and directories**.
- Support for **custom output names** and **custom storage locations**.
- Fully tested with **unit and integration tests**.
- *Blazingly faaast 🦀*


## Usage overview
### Display general usage information and examples

    help

For detailed help on a specific command:
    
    help <command>

### Encrypt a file
To encrypt a file you can use the *encrypt* (shorthand *e*) command:

    encrypt file.txt --name encrypted_file

### Descrypt a file
To decrypt a file you can use the *decrypt* (shorthand *d*) command: 

    decrypt encrypted_file 
