#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import os
import sys
import uuid

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.json import JSON
from rich.logging import RichHandler

# Configure consoles for standard and error output
console = Console()
error_console = Console(stderr=True)


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    """Derive a 32-byte master key from the password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def derive_stretched_keys(master_key: bytes) -> (bytes, bytes, bytes):
    """
    Derive separate 32-byte keys using HKDFExpand:
      - One with info=b"enc" for encryption (the AES key)
      - One with info=b"mac" for MAC
    Returns a tuple: (encryption_key, mac_key, stretched_master_key)
    where stretched_master_key is the concatenation of the two.
    """
    hkdf_enc = HKDFExpand(
        algorithm=hashes.SHA256(), length=32, info=b"enc", backend=default_backend()
    )
    encryption_key = hkdf_enc.derive(master_key)

    hkdf_mac = HKDFExpand(
        algorithm=hashes.SHA256(), length=32, info=b"mac", backend=default_backend()
    )
    mac_key = hkdf_mac.derive(master_key)

    stretched_master_key = encryption_key + mac_key
    return encryption_key, mac_key, stretched_master_key


def decrypt_payload(encrypted: str, key: bytes) -> bytes:
    """
    Decrypt a Bitwarden payload.

    Expected format: "2.<IV>|<ciphertext>|<hmac>"
    (HMAC is not verified in this example.)
    """
    if not encrypted.startswith("2."):
        raise ValueError("Unsupported payload version")

    payload = encrypted[2:]
    parts = payload.split("|")
    if len(parts) < 3:
        raise ValueError("Invalid encrypted payload format; expected 3 parts")

    # Remove all whitespace (including newlines) from each segment
    iv_b64 = "".join(parts[0].split())
    ciphertext_b64 = "".join(parts[1].split())
    mac_b64 = "".join(parts[2].split())

    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    mac = base64.b64decode(mac_b64)

    console.log(f"[blue]Decoded IV length: {len(iv)} bytes[/blue]")
    console.log(f"[blue]Decoded ciphertext length: {len(ciphertext)} bytes[/blue]")
    console.log(f"[blue]Decoded MAC length: {len(mac)} bytes[/blue]")

    if len(iv) != 16:
        raise ValueError(f"Invalid IV size ({len(iv)}) for CBC; expected 16 bytes.")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def decrypt_cipher_item(item, vault_key: bytes):
    """
    Recursively scan the dictionary or list values in a cipher item.
    For any string that starts with "2.", attempt to decrypt it using vault_key.
    """
    if isinstance(item, dict):
        for k, v in item.items():
            if isinstance(v, str) and v.startswith("2."):
                try:
                    dec = decrypt_payload(v, vault_key).decode("utf-8")
                    item[k] = dec
                except Exception as e:
                    item[k] = f"Decryption error: {e}"
            elif isinstance(v, dict) or isinstance(v, list):
                item[k] = decrypt_cipher_item(v, vault_key)
    elif isinstance(item, list):
        for i in range(len(item)):
            item[i] = decrypt_cipher_item(item[i], vault_key)
    return item


class BitwardenClient:
    def __init__(
        self,
        api_url="https://api.bitwarden.com",
        identity_url="https://identity.bitwarden.com",
        debug=False,
    ):
        self.api_url = api_url.rstrip("/")
        self.identity_url = identity_url.rstrip("/")
        self.access_token = None
        self.auth_data = {}  # store full auth response
        self.debug = debug
        self.session = requests.Session()
        self.device_id = str(uuid.uuid4())

        logging.basicConfig(
            level=logging.DEBUG if debug else logging.INFO,
            format="%(message)s",
            handlers=[RichHandler(console=error_console, show_time=False)],
        )
        self.logger = logging.getLogger("bitwarden")
        if debug:
            self.logger.setLevel(logging.DEBUG)

    def _redact_sensitive(self, data: dict) -> dict:
        sensitive_keys = ["password", "client_id", "client_secret"]
        return {
            k: "***REDACTED***" if any(s in k.lower() for s in sensitive_keys) else v
            for k, v in data.items()
        }

    # Only API key authentication is enabled.
    def login(self, client_id, client_secret):
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "api",
            "deviceType": 3,
            "deviceIdentifier": self.device_id,
            "deviceName": "Python CLI Client",
        }
        self.logger.debug(f"API key auth with data: {self._redact_sensitive(data)}")
        self._auth_request(data)

    def _auth_request(self, data):
        url = f"{self.identity_url}/connect/token"
        headers = {}
        self.logger.debug(f"Auth request to {url} with headers: {headers}")
        self.logger.debug(
            f"Sending POST request with data: {self._redact_sensitive(data)}"
        )
        try:
            response = self.session.post(url, data=data, headers=headers)
        except Exception as e:
            self.logger.debug(f"Error during request: {e}")
            raise Exception(f"Request failed: {e}")
        self.logger.debug(
            f"Auth response: {response.status_code} (Content length: {len(response.text)})"
        )
        if self.debug:
            self.logger.debug(f"Auth response text: {response.text}")
        try:
            response.raise_for_status()
            self.auth_data = response.json()
            self.access_token = self.auth_data.get("access_token")
            if not self.access_token:
                raise Exception("No access token in response")
        except Exception as e:
            raise Exception(f"Authentication failed: {e}")

    def sync(self):
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = self.session.get(f"{self.api_url}/sync", headers=headers)
        response.raise_for_status()
        return response.json()


def main():
    parser = argparse.ArgumentParser(
        description="Bitwarden CLI Client (API key auth only, with full decryption of vault items)"
    )
    parser.add_argument(
        "--api-url",
        default="https://api.bitwarden.com",
        help="Base API URL (default: %(default)s)",
    )
    parser.add_argument(
        "--identity-url",
        default="https://identity.bitwarden.com",
        help="Identity service URL (default: %(default)s)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    # API key authentication parameters
    auth = parser.add_argument_group("Authentication")
    auth.add_argument("--client-id", required=True, help="API client ID")
    auth.add_argument("--client-secret", required=True, help="API client secret")

    # Decryption credentials (used for key derivation)
    decryption = parser.add_argument_group("Decryption")
    decryption.add_argument(
        "--email", required=True, help="Account email (used as salt for key derivation)"
    )
    decryption.add_argument(
        "--password", help="Account password (use env BW_PASSWORD or provide here)"
    )

    args = parser.parse_args()

    master_email = args.email.strip().lower()
    master_password = args.password or os.getenv("BW_PASSWORD")
    if not master_password:
        master_password = console.input("[bold]Enter password: [/]", password=True)

    client = BitwardenClient(
        api_url=args.api_url, identity_url=args.identity_url, debug=args.debug
    )

    try:
        client.login(client_id=args.client_id, client_secret=args.client_secret)
        sync_data = client.sync()
        console.print(JSON(json.dumps(sync_data, indent=2)))
        profile = sync_data.get("profile", {})
        encrypted_vault_key = profile.get("key")
        if encrypted_vault_key:
            # Get iteration count from profile or auth data:
            kdf_iterations = profile.get("kdfIterations") or profile.get(
                "KdfIterations"
            )
            if kdf_iterations is None:
                kdf_iterations = client.auth_data.get(
                    "KdfIterations"
                ) or client.auth_data.get("kdfIterations")
            if kdf_iterations is None:
                kdf_iterations = 600000 if profile.get("premium") else 100000
            else:
                kdf_iterations = int(kdf_iterations)

            console.log(f"[blue]Using {kdf_iterations} iterations for PBKDF2.[/blue]")
            master_key = derive_key(
                master_password, master_email.encode(), kdf_iterations
            )
            encryption_key, mac_key, stretched_master_key = derive_stretched_keys(
                master_key
            )
            console.log(
                f"[blue]Using derived encryption key (HKDFExpand with info 'enc').[/blue]"
            )

            try:
                vault_key = decrypt_payload(encrypted_vault_key, encryption_key)
                console.log("[green]Successfully decrypted vault key.[/green]")
            except Exception as e:
                console.log(f"[red]Failed to decrypt vault key: {e}[/red]")
                vault_key = None

            if vault_key:
                console.log(f"[blue]Vault key length: {len(vault_key)} bytes[/blue]")
                # If the vault key is 64 bytes, assume it is two concatenated 32-byte keys.
                if len(vault_key) == 64:
                    item_decryption_key = vault_key[:32]
                    console.log(
                        "[blue]Using first 32 bytes of vault key for item decryption.[/blue]"
                    )
                else:
                    item_decryption_key = vault_key
                decrypted_items = []
                ciphers = sync_data.get("ciphers", [])
                for cipher in ciphers:
                    decrypted_items.append(
                        decrypt_cipher_item(cipher, item_decryption_key)
                    )
                console.print(JSON(json.dumps(decrypted_items, indent=2)))
        else:
            console.log(
                "[yellow]Profile information for decryption not found in sync data.[/yellow]"
            )
    except Exception as e:
        error_console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
