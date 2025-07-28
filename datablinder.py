# =============================================================================
# DataBlinder - Reversible Tokenization Framework
# =============================================================================

# Description:
#   DataBlinder is a background tool that tokenizes sensitive information 
#   from the clipboard using customizable regex rules, enabling reversible 
#   masking for secure AI interactions and privacy-preserving workflows.
#
# Repository:
#   https://github.com/datablinder/dataBlinder
#
# Author:
#   Arnaldo Duarte (https://github.com/arduarte67)
#
# License:
#   MIT License - See LICENSE file for details.
#
# Created:
#   2025-07-27
#
# Usage:
#   - Select a text
#   - Press Ctrl+C to copy selected text to
#   - Press Ctrl+Alt+T to tokenize clipboard text.
#   - Press Ctrl+V to copy the tokenized text to LLM pronpt, for exemple
#   - Select the response text
#   - Press Ctrl+Alt+R to reverse the tokenized content.
#   - Press Ctrl+V to past the detokenized text
#
# Configuration:
#   - rules.cfg: regex rules for masking.
#   - header.cfg (optional): header prepended to tokenized output.
#   - DATABLINDER_KEY: 16-char secure password required as environment variable.
#
# Disclaimer:
#   This software is provided "as is", without warranty of any kind.

# =============================================================================


import os
import re
import sys
import hashlib
import base64
import pyperclip # type: ignore
import time
import keyboard # type: ignore
import ctypes
from datetime import datetime, timezone
import tkinter as tk
from tkinter import messagebox



from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from plyer import notification
import psutil  # To capture the PID of the process

# ========================
# CONFIGURATION
# ========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(SCRIPT_DIR, "rules.cfg")
HEADER_FILE = os.path.join(SCRIPT_DIR, "header.cfg")
DEBUG_FILE = os.path.join(SCRIPT_DIR, "datablinder.dbg")

# Capture the current timestamp at start of execution (UTC)
SESSION_TIMESTAMP = datetime.now(timezone.utc).isoformat()


# Stores the encrypted data in memory
encrypted_rev_data = None
reversal_hash = None

# Checks if debug mode is enabled
DEBUG_MODE = "-d" in sys.argv

# Gets the base key from the environment DATABLINDER_KEY (16 character strong password)
DATABLINDER_KEY = os.getenv("DATABLINDER_KEY")
if not DATABLINDER_KEY or len(DATABLINDER_KEY) < 16:
   notification.notify(
        title="DataBlinder",
        message="DATABLINDER_KEY must exist and be a secure 16 or more character string set in environment.",
        app_name="DataBlinder",
        timeout=3
    )
   sys.exit(1)

# Generates the AES key based on the key and timestamp combination
AES_KEY = hashlib.sha256((DATABLINDER_KEY + SESSION_TIMESTAMP).encode()).digest()


# ========================
# HELPER FUNCTIONS
# ========================

def log_debug(message):
    """Logs messages to debug file if -d mode is enabled."""
    if DEBUG_MODE:
        with open(DEBUG_FILE, "a", encoding="utf-8") as dbg:
            dbg.write(f"[{datetime.now().isoformat()}] {message}\n")

def encrypt_text(text, key):
    """Encrypts a text using AES-256-CBC with PKCS7 padding."""
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(text.encode("utf-8")) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ciphertext).decode("utf-8")
    except Exception as e:
        log_debug(f"**Error encrypting:: \n\n{str(e)}\n")
        return None

def decrypt_text(encrypted_text, key):
    """Decrypts text encrypted with AES-256-CBC and PKCS7 padding."""
    try:
        data = base64.b64decode(encrypted_text)
        iv, ciphertext = data[:16], data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
        return decrypted.decode("utf-8")
    except Exception as e:
        log_debug(f"**ERROR: decrypting: \n\n{str(e)}\n")
        return None

def get_clipboard_text():
    """Reads and returns the clipboard text."""
    time.sleep(0.5)  # Small delay to ensure the copy operation is complete
    text = pyperclip.paste()
    
    if not text:
        log_debug("**No text found in clipboard!")
        show_notification("DataBlinder", "ERROR: No text found in clipboard!")
        return None

    log_debug(f"Clipboard: \n\n{text}\n")
    return text

def load_rules():
    """Loads rules from rules.cfg file."""
    if not os.path.exists(RULES_FILE):
        return []
    
    rules = []
    with open(RULES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and "," in line:
                data_type, pattern = line.split(",", 1)
                rules.append((data_type.strip(), pattern.strip()))
    return rules

def show_notification(title, message):
    """Displays a Windows notification and logs it if debug mode is enabled."""
    log_debug(f"Notification: {title} - {message}")
    notification.notify(
        title=title,
        message=message,
        app_name="DataBlinder",
        timeout=3
    )

def tokenize_text():
    """Tokenizes text from the clipboard using regex rules and replaces clipboard content."""
    global encrypted_rev_data, reversal_hash

    input_text = get_clipboard_text()
    if not input_text:
        return

    timestamp = datetime.utcnow().isoformat()
    rules = load_rules()
    token_map = {}

    for data_type, pattern in rules:
        matches = re.findall(pattern, input_text)
        for match in matches:
            if match not in token_map:
                token = f"#DB-{data_type.upper()}-{hashlib.sha256(match.encode()).hexdigest()[:8]}"
                token_map[match] = token

    tokenized_text = input_text
    for original, token in token_map.items():
        tokenized_text = tokenized_text.replace(original, token)

    rev_data = "\n".join([f"{token},{original}" for original, token in token_map.items()])
    encrypted_rev_data = encrypt_text(rev_data, AES_KEY)

    # Create hash for identification
    reversal_hash = hashlib.sha256(rev_data.encode()).hexdigest()[:8]

    # Adds the header from `header.cfg` file, if it exists
    header_content = ""
    if os.path.exists(HEADER_FILE):
        with open(HEADER_FILE, "r", encoding="utf-8") as hf:
            header_content = hf.read().strip() + "\n\n"  # Adds an extra line after the header

    # Assembles the final text with header
    final_text = f"{header_content}{tokenized_text}"

    # Overwrites clipboard with tokenized text
    pyperclip.copy(final_text)

    log_debug(f"Tokenized Text: \n\n{tokenized_text}\n")

    
    show_notification("DataBlinder", "TOKENIZED TEXT READY! Use Ctrl+V to paste.")

def reverse_text():
    """Reads the clipboard text."""
    global encrypted_rev_data

    if not encrypted_rev_data:
        show_notification("DataBlinder", "ERROR: No tokenized data available! You must tokenize first!")
        log_debug("**ERROR: Attempted reversal without available reversal data.")
        return

    input_text = get_clipboard_text()
    if not input_text:
        return
    
    # Remove header content if present
    if os.path.exists(HEADER_FILE):
        with open(HEADER_FILE, "r", encoding="utf-8") as hf:
            header_content = hf.read().strip()
            if header_content and header_content in input_text:
                input_text = input_text.replace(header_content, "", 1).lstrip()

    try:
        decrypted_data = decrypt_text(encrypted_rev_data, AES_KEY)  # return string
        rev_map = []

        for line in decrypted_data.split("\n"):  # Removed `.decode()`
            if "," in line:
                token, original = line.strip().split(",", 1)
                rev_map.append((token, original))

        rev_map.sort(key=lambda x: len(x[0]), reverse=True)

        reversed_text = input_text
        for token, original in rev_map:
            reversed_text = reversed_text.replace(token, original)

        pyperclip.copy(reversed_text)

        log_debug(f"Detokenized text:: \n\n{reversed_text}\n")
        show_notification("DataBlinder", "REVERSED TEXT READY! Use Ctrl+V to paste.")

    except Exception as e:
        log_debug(f"**ERROR during reversion: \n\n{str(e)}\n")
        show_notification("DataBlinder", "ERROR during reversion.")


def show_debug_warning():
    if DEBUG_MODE:
        root = tk.Tk()
        root.withdraw()  # Esconde a janela principal

        user_response = messagebox.askquestion(
            "⚠️ DataBlinder Debug Mode",
            "Debug mode is enabled by -d flag.\n\nSensitive data will be logged in plain text to 'datablinder.dbg'.\n\nDo you accept the risks and continue?",
            icon='warning'
        )

        if user_response != "yes":
            messagebox.showinfo("DataBlinder", "Execution aborted by user.")
            sys.exit(0)

# ========================
# HOTKEYS AND BACKGROUND
# ========================
def main():

    
    if DEBUG_MODE:
        show_debug_warning()
        log_debug(f"DataBlinder started with PID {psutil.Process().pid}")

    keyboard.add_hotkey("ctrl+alt+t", tokenize_text)
    keyboard.add_hotkey("ctrl+alt+r", reverse_text)
    show_notification("DataBlinder", "Running in background...")

    keyboard.wait()

if __name__ == "__main__":
    main()
