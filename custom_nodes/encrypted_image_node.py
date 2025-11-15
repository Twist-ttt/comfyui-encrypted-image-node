import os
import io
import torch
import base64
import hashlib

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# ===========================
# Utility: key derivation & encrypt/decrypt
# ===========================

MAGIC_HEADER = b"CUIE"  # ComfyUI Image Encrypted
SALT_SIZE = 16          # 16 bytes salt
PBKDF_ITER = 200_000    # PBKDF2 iterations


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte key from password + salt using PBKDF2,
    then encode it for Fernet.
    """
    password_bytes = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF_ITER,
        backend=default_backend(),
    )
    key = kdf.derive(password_bytes)
    return base64.urlsafe_b64encode(key)


def encrypt_tensor(images: torch.Tensor, password: str) -> bytes:
    """
    Serialize IMAGE tensor and encrypt it.

    File format:
    [MAGIC_HEADER][SALT(16)][FERNET_TOKEN...]
    """
    # Serialize tensor
    buf = io.BytesIO()
    torch.save({"images": images}, buf)
    data = buf.getvalue()

    # Generate random salt
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    f = Fernet(key)

    # Encrypt
    token = f.encrypt(data)
    return MAGIC_HEADER + salt + token


def decrypt_tensor(enc_bytes: bytes, password: str) -> torch.Tensor:
    """
    Decrypt bytes and return IMAGE tensor.
    """
    if not enc_bytes.startswith(MAGIC_HEADER):
        raise ValueError("Invalid .cui file: MAGIC HEADER mismatch.")

    salt = enc_bytes[len(MAGIC_HEADER):len(MAGIC_HEADER) + SALT_SIZE]
    token = enc_bytes[len(MAGIC_HEADER) + SALT_SIZE:]

    key = derive_key(password, salt)
    f = Fernet(key)

    try:
        data = f.decrypt(token)
    except Exception as e:
        raise ValueError("Decryption failed. Wrong password or corrupted file.") from e

    buf = io.BytesIO(data)
    obj = torch.load(buf, map_location="cpu")
    if not isinstance(obj, dict) or "images" not in obj:
        raise ValueError("Decrypted content missing 'images' field.")
    return obj["images"]


# ===========================
# ComfyUI Node 1: Encrypt to file
# ===========================

class EncryptImagesToFile:
    """
    Encrypt ComfyUI IMAGE (single or batch / video frames) into a binary file (.cui).
    Output file is saved under ComfyUI/output by default.
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "images": ("IMAGE",),
                "password": ("STRING", {
                    "multiline": False,
                    "default": "",
                }),
                "filename_prefix": ("STRING", {
                    "multiline": False,
                    "default": "encrypted_images",
                }),
            }
        }

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("file_path",)
    FUNCTION = "encrypt_to_file"
    CATEGORY = "encryption"

    def encrypt_to_file(self, images: torch.Tensor, password: str, filename_prefix: str):
        if not password:
            raise ValueError("Password must not be empty.")

        enc_bytes = encrypt_tensor(images, password)

        # ComfyUI root directory
        cwd = os.getcwd()
        output_dir = os.path.join(cwd, "output")
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename with short hash
        h = hashlib.sha256(enc_bytes[:64]).hexdigest()[:8]
        filename = f"{filename_prefix}_{h}.cui"
        file_path = os.path.join(output_dir, filename)

        with open(file_path, "wb") as f:
            f.write(enc_bytes)

        # Return relative path (from ComfyUI root)
        rel_path = os.path.relpath(file_path, cwd)
        return (rel_path,)


# ===========================
# ComfyUI Node 2: Decrypt from file
# ===========================

class DecryptImagesFromFile:
    """
    Decrypt IMAGE from an encrypted .cui file.
    """

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "file_path": ("STRING", {
                    "multiline": False,
                    "default": "output/encrypted_images_xxxxx.cui",
                }),
                "password": ("STRING", {
                    "multiline": False,
                    "default": "",
                }),
            }
        }

    RETURN_TYPES = ("IMAGE",)
    RETURN_NAMES = ("images",)
    FUNCTION = "decrypt_from_file"
    CATEGORY = "encryption"

    def decrypt_from_file(self, file_path: str, password: str):
        if not password:
            raise ValueError("Password must not be empty.")

        cwd = os.getcwd()
        if not os.path.isabs(file_path):
            file_path = os.path.join(cwd, file_path)

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            enc_bytes = f.read()

        images = decrypt_tensor(enc_bytes, password)
        if not isinstance(images, torch.Tensor):
            raise ValueError("Decrypted result is not a Tensor.")
        return (images,)


NODE_CLASS_MAPPINGS = {
    "EncryptImagesToFile": EncryptImagesToFile,
    "DecryptImagesFromFile": DecryptImagesFromFile,
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "EncryptImagesToFile": "Encrypt Images to File",
    "DecryptImagesFromFile": "Decrypt Images from File",
}