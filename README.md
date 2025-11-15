# ComfyUI Encrypted Image Node

Custom nodes for ComfyUI to:

- Encrypt IMAGE tensors (single image, batch, or video frames) into an encrypted `.cui` file.
- Decrypt `.cui` files back to IMAGE inside ComfyUI.

## Installation

1. Clone this repo:

```bash
git clone https://github.com/Twist-ttt/comfyui-encrypted-image-node.git
cd comfyui-encrypted-image-node
```

2. Install dependencies (in the same Python environment as ComfyUI):

```bash
pip install -r requirements.txt
```

3. Copy the custom node file into your ComfyUI directory:

```bash
cp -r custom_nodes /path/to/ComfyUI/
# or:
# cp custom_nodes/encrypted_image_node.py /path/to/ComfyUI/custom_nodes/
```

4. Restart ComfyUI.

## Nodes

### Encrypt Images to File
**Category:** encryption

**Inputs:**
- `images` (IMAGE)
- `password` (STRING)
- `filename_prefix` (STRING)

**Output:**
- `file_path` (STRING) → e.g. `output/encrypted_XXXX.cui`

### Decrypt Images from File
**Category:** encryption

**Inputs:**
- `file_path` (STRING) → e.g. `output/encrypted_XXXX.cui`
- `password` (STRING)

**Output:**
- `images` (IMAGE)

## File Format

```
MAGIC_HEADER = "CUIE"
16 bytes salt
Fernet token (AES-based encryption + HMAC)
```

## Usage Example

1. Use any image generation or loading node to get an IMAGE tensor
2. Connect it to "Encrypt Images to File" node
3. Set a password and filename prefix
4. Run the workflow to generate a `.cui` file
5. Use "Decrypt Images from File" node with the same password to recover the images

## Security Notes

- Uses PBKDF2 with 200,000 iterations for key derivation
- Encryption uses Fernet (AES 128 in CBC mode + HMAC SHA256)
- Password should be strong and memorable - lost passwords cannot be recovered
- Salt is randomly generated for each encryption operation

## License

This project is provided as-is for educational and personal use.