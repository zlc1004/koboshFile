import os
import zipfile
from Crypto.Cipher import AES
import base64
import json
import io
import hashlib
import shutil

# --- KoboshPhrase ---
class KoboshPhrase:
    wordlist = "kobosh joei emo gluttonous tender juicy chewable edible tasty reporter turth kobosher gyat brown orange black mia indian kimchi gas chamber telegram paradox gyatman massive low taper fade koboshian crowbar connavon skibidi".lower().split(
        " "
    )
    b32alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    @classmethod
    def from_phrase(cls, phrase: str):
        words = phrase.strip().split()
        if len(words) < 3:
            return None, "Key phrase too short."
        try:
            chars = [
                cls.b32alphabet[cls.wordlist.index(w)]
                for w in words
                if w in cls.wordlist
            ]
        except ValueError:
            return None, "Invalid word in key phrase."
        key_b32 = "".join(chars)
        key_b32_nopad = key_b32.replace("=", "")
        key_part = key_b32_nopad[:-2]
        checksum = key_b32_nopad[-2:]
        try:
            key_bytes = base64.b32decode(key_part + "=" * ((8 - len(key_part) % 8) % 8))
        except Exception:
            return None, "Key phrase could not be decoded."
        sha256key = sha256(io.BytesIO(key_bytes))
        sha256key_b32 = base64.b32encode(sha256key.encode()).decode()
        expected_checksum = sha256key_b32[:2]
        if checksum != expected_checksum:
            return None, "Key phrase is INVALID."
        return key_bytes, None

    @classmethod
    def to_phrase(cls, key_bytes: bytes):
        sha256key = sha256(io.BytesIO(key_bytes))
        key_b32 = base64.b32encode(key_bytes).decode()
        sha256key_b32 = base64.b32encode(sha256key.encode()).decode()
        key_b32 += sha256key_b32[:2]
        key_phrase = []
        for char in key_b32:
            if char == "=":
                continue
            idx = cls.b32alphabet.index(char)
            key_phrase.append(cls.wordlist[idx])
        return " ".join(key_phrase)

    @classmethod
    def is_valid(cls, phrase: str):
        key_bytes, err = cls.from_phrase(phrase)
        return err is None


class KoboshFile:
    def __init__(self, file_path=None, tmp_dir=None, log_widget=None):
        self.file = file_path
        self.dir = tmp_dir
        self.log_widget = log_widget
        self.metadata = {}
        self.last_phrase_str = None
        self.decryption_key_bytes = None

    def new256bitKey(self):
        return os.urandom(32)

    def new128bitKey(self):
        return os.urandom(16)

    def encrypt(self, file_path, tmp_dir, intensity):
        self.file = file_path
        self.dir = tmp_dir
        self.last_phrase_str = None
        self.metadata = {"original.name": os.path.basename(self.file), "sha256": sha256(open(self.file, "rb"))}
        # Split the original file into 'intensity' chunks of the same size
        file_size = os.path.getsize(self.file)
        chunk_size = file_size // intensity
        remainder = file_size % intensity
        chunks = []
        with open(self.file, "rb") as f:
            for i in range(intensity):
                size = chunk_size + (1 if i < remainder else 0)
                chunk = f.read(size)
                chunk_path = os.path.join(self.dir, f"chunk_{i+1:02d}")
                with open(chunk_path, "wb") as cf:
                    cf.write(chunk)
                chunks.append(chunk_path)
        new_chunks = []
        chunkhashes = []
        for chunk in chunks:
            with open(chunk, "rb") as f:
                sha256hash = sha256(f)
            root, ext = os.path.split(str(chunk))
            os.rename(chunk, os.path.join(root, sha256hash[:12]))
            new_chunks.append(os.path.join(root, sha256hash[:12]))
            chunkhashes.append(sha256hash)
        chunks = new_chunks.copy()
        self.metadata["chunks"] = chunkhashes
        keys = []
        for chunk in chunks:
            with open(chunk, "rb") as f:
                data = f.read()
                key = self.new256bitKey()
                cipher = AES.new(key, AES.MODE_EAX)
                ciphertext = cipher.encrypt(data)
                encrypted_chunk_path = chunk + ".enc"
                with open(encrypted_chunk_path, "wb") as ef:
                    ef.write(cipher.nonce + ciphertext)
                keys.append(base64.b85encode(key).decode())
        self.metadata["keys"] = keys
        # Create a zip file with the encrypted chunks and metadata
        zip_path = os.path.join(self.dir, f"{os.path.basename(self.file)}.kobosh")
        json_metadata = base64.b85encode(json.dumps(self.metadata).encode()).decode()
        bit128key = self.new128bitKey()
        cipher = AES.new(bit128key, AES.MODE_EAX)
        encrypted_metadata = cipher.encrypt(json_metadata.encode())
        with zipfile.ZipFile(zip_path, "w") as zipf:
            for chunk in chunks:
                zipf.write(chunk + ".enc", arcname=os.path.basename(chunk) + ".enc")
            metadata_path = os.path.join(self.dir, "metadata.json")
            with open(metadata_path, "wb") as mf:
                mf.write(cipher.nonce + encrypted_metadata)
            zipf.write(metadata_path, arcname="metadata.json")
        # Move .kobosh file to main directory
        main_dir = os.getcwd()
        final_path = os.path.join(main_dir, f"{os.path.basename(self.file)}.kobosh")
        os.rename(zip_path, final_path)
        shutil.rmtree(self.dir)
        # Generate key phrase for decrypting metadata using KoboshPhrase
        phrase_str = KoboshPhrase.to_phrase(bit128key)
        self.last_phrase_str = phrase_str
        return final_path, phrase_str


    def decrypt(self, kobosh_path, decryption_key_bytes):
        # Only accept .kobosh files
        if not str(kobosh_path).endswith(".kobosh"):
            raise ValueError("Please select a .kobosh file.")
        tmp_dir = os.path.join(os.getcwd(), "tmp_decrypt")
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)
        with zipfile.ZipFile(kobosh_path, "r") as zipf:
            zipf.extractall(tmp_dir)
        metadata_path = os.path.join(tmp_dir, "metadata.json")
        if not os.path.exists(metadata_path):
            raise FileNotFoundError("metadata.json not found in archive.")
        with open(metadata_path, "rb") as mf:
            nonce = mf.read(16)
            encrypted_metadata = mf.read()
        cipher = AES.new(decryption_key_bytes, AES.MODE_EAX, nonce=nonce)
        try:
            json_metadata = cipher.decrypt(encrypted_metadata)
            metadata = json.loads(base64.b85decode(json_metadata).decode())
        except Exception:
            raise ValueError("Failed to decrypt metadata.")
        chunk_hashes = metadata["chunks"]
        chunk_keys = metadata["keys"]
        original_name = metadata["original.name"]
        decrypted_chunks = []
        for i, chunk_hash in enumerate(chunk_hashes):
            enc_chunk_path = os.path.join(tmp_dir, chunk_hash[:12] + ".enc")
            if not os.path.exists(enc_chunk_path):
                raise FileNotFoundError(f"Encrypted chunk {enc_chunk_path} not found.")
            with open(enc_chunk_path, "rb") as ef:
                nonce = ef.read(16)
                ciphertext = ef.read()
            key = base64.b85decode(chunk_keys[i])
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            try:
                chunk_data = cipher.decrypt(ciphertext)
            except Exception:
                raise ValueError(f"Failed to decrypt chunk {i+1}.")
            chunk_hash_actual = sha256(io.BytesIO(chunk_data))
            if chunk_hash_actual != chunk_hash:
                raise ValueError(f"Chunk {i+1} hash mismatch! Expected {chunk_hash}, got {chunk_hash_actual}")
            chunk_out_path = os.path.join(tmp_dir, f"chunk_{i+1:02d}.dec")
            with open(chunk_out_path, "wb") as cf:
                cf.write(chunk_data)
            decrypted_chunks.append(chunk_out_path)
        output_path = os.path.join(tmp_dir, original_name)
        with open(output_path, "wb") as outf:
            for chunk_path in decrypted_chunks:
                with open(chunk_path, "rb") as cf:
                    outf.write(cf.read())
        with open(output_path, "rb") as outf:
            final_hash = sha256(outf)
        if final_hash != metadata["sha256"]:
            raise ValueError(f"Final file hash mismatch! Expected {metadata['sha256']}, got {final_hash}")
        final_path = os.path.join(os.getcwd(), original_name)
        shutil.move(output_path, final_path)
        shutil.rmtree(tmp_dir)
        return final_path

@staticmethod
def sha256(stream):
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: stream.read(4096), b""):
        sha256.update(chunk)
    return sha256.hexdigest()