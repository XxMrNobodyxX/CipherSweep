import json
import os

def load_cipher_list(filename):
    """Load a cipher list from a JSON file."""
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading cipher list from {filename}: {e}")
        return []

script_dir = os.path.dirname(os.path.abspath(__file__))

STRONG_CIPHERS = load_cipher_list(os.path.join(script_dir, 'strong_ciphers.json'))
WEAK_CIPHERS = load_cipher_list(os.path.join(script_dir, 'weak_ciphers.json'))

def get_strong_ciphers():
    """Return the list of strong ciphers."""
    return STRONG_CIPHERS

def get_weak_ciphers():
    """Return the list of weak ciphers."""
    return WEAK_CIPHERS

def is_strong_cipher(cipher):
    """Check if a cipher is in the strong ciphers list."""
    return any(strong_cipher in cipher for strong_cipher in STRONG_CIPHERS) or cipher.startswith("TLS_AKE_")

def is_weak_cipher(cipher):
    """Check if a cipher is in the weak ciphers list."""
    return any(weak_cipher in cipher for weak_cipher in WEAK_CIPHERS) 