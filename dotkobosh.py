from textual.widgets import DirectoryTree
from textual.containers import Center
from textual.widgets import Button, Static
from textual.widgets import ProgressBar, Button, Static, Input, DirectoryTree
from textual.containers import Center, Vertical, Horizontal
from textual import events
from textual.app import ComposeResult, App, Binding, SystemCommand
from textual.widget import Widget
from textual.color import Gradient
from textual.widgets import Log
import os
import zipfile
from Crypto.Cipher import AES
import base64
import json
import io
import hashlib
import shutil
from textual.widgets import Footer
from textual.screen import Screen
from typing import Iterable


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


# CustomSliderWidget for encryption intensity selection using ProgressBar
class CustomSliderWidget(Widget):
    can_focus = True

    def on_mount(self):
        self.focus()

    def __init__(self, on_submit=None, minimum=3, maximum=15, value=5):
        super().__init__()
        self.on_submit = on_submit
        self.minimum = minimum
        self.maximum = maximum
        self.value = value

        gradient = Gradient.from_colors(
            *["#44dd88", "#99dd55", "#eedd00", "#ee9944", "#cc6666", "#aa3355"]
        )

        self.progress = ProgressBar(
            total=maximum,
            show_percentage=False,
            show_eta=False,
            id="intensity-bar",
            gradient=gradient,
        )
        self.progress.update(progress=value)
        self.value_label = Static(f"Intensity: {self.value}", id="intensity-value")
        self.submit_btn = Button("Submit", id="submit-intensity")

    def compose(self) -> ComposeResult:
        yield Center(
            Vertical(
                Center(
                    Static("Select encryption intensity (3-10):", id="intensity-title"),
                    id="intensity-title-center",
                ),
                Center(self.value_label, id="intensity-value-center"),
                Center(self.progress, id="intensity-bar-center"),
                Center(self.submit_btn, id="intensity-btn-center"),
                id="intensity-box",
            ),
            id="intensity-center",
        )

    def on_key(self, event: events.Key) -> None:
        if event.key == "left":
            if self.value > self.minimum:
                self.value -= 1
                self.progress.update(progress=self.value)
                self.value_label.update(f"Intensity: {self.value}")
            event.stop()
        elif event.key == "right":
            if self.value < self.maximum:
                self.value += 1
                self.progress.update(progress=self.value)
                self.value_label.update(f"Intensity: {self.value}")
            event.stop()

    def on_button_pressed(self, event):
        if event.button.id == "submit-intensity" and self.on_submit:
            self.on_submit(self.value)
            self.remove()
        # ...existing code...


# --- Textual App Implementation ---


class SuggestionInputWidget(Widget):
    def __init__(self, on_submit=None):
        super().__init__()
        self.input_text = ""
        self.suggestions = []
        self.selected_idx = 0
        self.suggestion_bar = Static("", id="suggestion")
        self.input_box = Input(placeholder="Type a word...", id="input")
        self.on_submit = on_submit

    def compose(self) -> ComposeResult:
        yield Vertical(
            self.suggestion_bar,
            self.input_box,
            id="centered",
        )

    def on_mount(self):
        self.input_box.focus()
        self.update_suggestions()

    def update_suggestions(self):
        words = self.input_text.strip().split()
        fragment = words[-1] if words else ""
        filtered = (
            [w for w in KoboshPhrase.wordlist if w.startswith(fragment)]
            if fragment
            else KoboshPhrase.wordlist
        )
        filtered = sorted(filtered)
        self.suggestions = filtered[:8]
        self.selected_idx = 0
        self.render_suggestions()

    def render_suggestions(self):
        out = []
        for i, word in enumerate(self.suggestions):
            if i == self.selected_idx:
                out.append(f"[reverse]{word}[/reverse]")
            else:
                out.append(word)
        self.suggestion_bar.update("  ".join(out))

    def on_input_changed(self, event: Input.Changed):
        self.input_text = event.value
        self.update_suggestions()

    def on_click(self, event: events.Click) -> None:
        # Only handle clicks on suggestion bar
        if getattr(event.control, "id", None) != "suggestion":
            return
        x = event.offset.x
        num_suggestions = len(self.suggestions)
        if num_suggestions == 0:
            return
        # Get the width of the suggestion bar
        bar_width = event.control.size.width if hasattr(event.control, "size") else 60
        # Divide the bar into equal regions for each suggestion
        region_width = bar_width / num_suggestions
        idx = int(x // region_width)
        idx = max(0, min(idx, num_suggestions - 1))
        if self.suggestions:
            words = self.input_text.strip().split()
            if not words or words[-1] not in wordlist:
                if words:
                    words[-1] = self.suggestions[idx]
                else:
                    words = [self.suggestions[idx]]
                self.input_text = " ".join(words)
            else:
                self.input_text += " "
            self.input_box.value = self.input_text
            self.input_box.cursor_position = len(self.input_text)
            self.update_suggestions()

    def on_key(self, event: events.Key) -> None:
        if event.key == "tab":
            self.action_insert_word()
            event.stop()
        elif event.key == "up":
            self.action_move_up()
            event.stop()
        elif event.key == "down":
            self.action_move_down()
            event.stop()
        elif event.key == "enter":
            if self.on_submit:
                self.on_submit(self.input_box.value)
            self.remove()
            event.stop()
        elif event.key == "space":
            # Only reset if event is from input box
            if event.control is self.input_box:
                self.input_text = self.input_box.value
                self.suggestions = sorted(wordlist)[:8]
                self.selected_idx = 0
                self.render_suggestions()

    def action_move_up(self):
        if self.suggestions:
            self.selected_idx = (self.selected_idx - 1) % len(self.suggestions)
            self.render_suggestions()

    def action_move_down(self):
        if self.suggestions:
            self.selected_idx = (self.selected_idx + 1) % len(self.suggestions)
            self.render_suggestions()

    def action_insert_word(self):
        if self.suggestions:
            words = self.input_text.strip().split()
            if not words or words[-1] not in wordlist:
                if words:
                    words[-1] = self.suggestions[self.selected_idx]
                else:
                    words = [self.suggestions[self.selected_idx]]
                self.input_text = " ".join(words)
            else:
                self.input_text += " "
            self.input_box.value = self.input_text
            self.input_box.cursor_position = len(self.input_text)
            self.update_suggestions()


class ChoiceMenu(Widget):
    def __init__(self, on_choice=None):
        super().__init__()
        self.on_choice = on_choice

    def compose(self) -> ComposeResult:
        yield Center(
            Vertical(
                Static("Choose an action:", id="menu-title"),
                Static("Use ctrl + p to open the command palette", id="menu-instructions"),
                Horizontal(
                    Button("Encrypt", id="encrypt"),
                    Button("Decrypt", id="decrypt"),
                    id="menu-buttons",
                ),
                id="menu-box",
            ),
            id="menu-center",
        )

    def on_button_pressed(self, event):
        if self.on_choice:
            self.on_choice(event.button.id)
        self.remove()


class KoboshTextualApp(App):
    CSS = """
    #centered {
        align: center middle;
        height: 100vh;
    }
    #suggestion {
        width: 60;
        margin-bottom: 1;
        text-align: center;
    }
    #input {
        width: 60;
        text-align: center;
    }
    #file-input {
        width: 60;
        text-align: center;
    }
    #file-box {
        align: center middle;
        padding: 2;
        border: solid #888;
        width: auto;
        background: $panel;
    }
    #file-title {
        text-align: center;
        margin-bottom: 1;
    }
    #menu-center {
        align: center middle;
        height: 100vh;
    }
    #menu-box {
        align: center middle;
        padding: 2;
        border: solid #888;
        width: auto;
        background: $panel;
    }
    #menu-buttons Button {
        width: auto;
        min-width: 8;
        padding-left: 2;
        padding-right: 2;
    }
    #menu-title {
        text-align: center;
        margin-bottom: 1;
    }
    #menu-buttons {
        align: center middle;
        margin-top: 1;
    }
    #encrypt {
        margin-right: 2;
    }
    """
    BINDINGS = [
        Binding(key="^q", action="quit", description="Quit the app"),
        Binding(key="^c", action="copy_phrase", description="Copy key phrase after encrypt",show=True),
    ]
    
    def get_system_commands(self, screen: Screen) -> Iterable[SystemCommand]:
        yield from super().get_system_commands(screen)  
        yield SystemCommand("Copy Your KoboshPhrase", "Copy your KoboshPhrase (only available in encrypt mode)", self.action_copy_phrase)  

    def compose(self) -> ComposeResult:
        yield Footer()
        def handle_choice(mode):
            self.selected_mode = mode
            if mode == "decrypt":
                self.suggestion_input = SuggestionInputWidget(
                    on_submit=self.handle_key_submit
                )
                self.mount(self.suggestion_input)
            elif mode == "encrypt":
                self.file_browser = FileBrowserWidget(on_submit=self.handle_file_submit)
                self.mount(self.file_browser)

        self.menu = ChoiceMenu(on_choice=handle_choice)
        yield self.menu


def sha256(stream):
    sha256 = hashlib.sha256()
    for chunk in iter(lambda: stream.read(4096), b""):
        sha256.update(chunk)
    return sha256.hexdigest()


class KoboshTextualApp(App):
    CSS = """
    #centered {
        align: center middle;
        height: 100vh;
    }
    #suggestion {
        width: 60;
        margin-bottom: 1;
        text-align: center;
    }
    #input {
        width: 60;
        text-align: center;
    }
    #file-input {
        width: 60;
        text-align: center;
    }
    #file-box {
        align: center middle;
        padding: 2;
        border: solid #888;
        width: auto;
        background: $panel;
    }
    #file-title {
        text-align: center;
        margin-bottom: 1;
    }
    #menu-center {
        align: center middle;
        height: 100vh;
    }
    #menu-box {
        align: center middle;
        padding: 2;
        border: solid #888;
        width: auto;
        background: $panel;
    }
    #menu-buttons Button {
        width: auto;
        min-width: 8;
        padding-left: 2;
        padding-right: 2;
    }
    #menu-title {
        text-align: center;
        margin-bottom: 1;
    }
    #menu-buttons {
        align: center middle;
        margin-top: 1;
    }
    #encrypt {
        margin-right: 2;
    }
    """

    def compose(self) -> ComposeResult:
        def handle_choice(mode):
            self.selected_mode = mode
            if mode == "decrypt":
                self.suggestion_input = SuggestionInputWidget(
                    on_submit=self.handle_key_submit
                )
                self.mount(self.suggestion_input)
            elif mode == "encrypt":
                self.file_browser = FileBrowserWidget(on_submit=self.handle_file_submit)
                self.mount(self.file_browser)

        self.menu = ChoiceMenu(on_choice=handle_choice)
        yield self.menu

    def handle_file_submit(self, path):
        # Ensure tmp directory exists
        tmp_dir = os.path.join(os.getcwd(), "tmp")
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)
        # Compute SHA256 hash of the file using sha256()
        with open(path, "rb") as f:
            hash_name = sha256(f)
        # Create subdirectory with hash name
        hash_dir = os.path.join(tmp_dir, hash_name)
        self.dir = hash_dir
        self.file = str(path).split("\\")[-1].split("/")[-1]
        self.metadata = {"original.name": self.file, "sha256": hash_name}
        if not os.path.exists(hash_dir):
            os.makedirs(hash_dir)
        self.notify(f"Encrypt file: {path}\nCreated directory: {hash_dir}")

        self.intensity_slider = CustomSliderWidget(
            on_submit=self.handle_intensity_submit, minimum=3, maximum=15, value=5
        )
        self.mount(self.intensity_slider)

        # Show intensity slider

    def handle_intensity_submit(self, intensity):
        self.last_phrase_str = None
        # Create a Log widget to display log messages
        self.log_widget = Log(id="encryption-log", highlight=True)
        self.mount(self.log_widget)
        self.log_widget.write(f"Selected encryption intensity: {intensity}" + "\n")
        self.log_widget.write(
            f"Processing file {self.file} with tmp dir {self.dir}" + "\n"
        )
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
            self.log_widget.write(f"Renamed {chunk} to {sha256hash}" + "\n")
            new_chunks.append(os.path.join(root, sha256hash[:12]))
            chunkhashes.append(sha256hash)
        chunks = new_chunks.copy()
        self.log_widget.write(f"Split file into {intensity} chunks:" + "\n")
        for chunk in chunks:
            self.log_widget.write(chunk + "\n")
        self.metadata["chunks"] = chunkhashes
        self.log_widget.write(str(self.metadata) + "\n")
        self.log_widget.write("Encrypting chunks" + "\n")
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
                self.log_widget.write(
                    f"Encrypted {chunk} to {encrypted_chunk_path}" + "\n"
                )
        self.metadata["keys"] = keys
        self.log_widget.write("Encryption complete!" + "\n")
        self.log_widget.write("Metadata: " + json.dumps(self.metadata, indent=2) + "\n")
        # Create a zip file with the encrypted chunks and metadata
        zip_path = os.path.join(self.dir, f"{self.file}.kobosh")
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
        final_path = os.path.join(main_dir, f"{self.file}.kobosh")
        os.rename(zip_path, final_path)
        self.log_widget.write(f"Moved .kobosh file to: {final_path}" + "\n")
        # Remove temp folder
        shutil.rmtree(self.dir)
        self.log_widget.write(f"Removed temp folder: {self.dir}" + "\n")

        # Generate key phrase for decrypting metadata using KoboshPhrase
        phrase_str = KoboshPhrase.to_phrase(bit128key)
        self.last_phrase_str = phrase_str
        self.log_widget.write(f"Key phrase to decrypt metadata:\n{phrase_str}\n")
    def action_copy_phrase(self):
        # Only allow if phrase_str is available
        if hasattr(self, "last_phrase_str") and self.last_phrase_str:
            import pyperclip
            pyperclip.copy(self.last_phrase_str)
            self.notify(f"Key phrase copied to clipboard!\n{self.last_phrase_str}")
        else:
            self.notify("No key phrase available. Encrypt a file first.")

    def new256bitKey(self):
        # Generate a random 32-byte (256-bit) key
        return os.urandom(32)

    def new128bitKey(self):
        # Generate a random 16-byte (128-bit) key
        return os.urandom(16)

    def handle_key_submit(self, value):
        key_bytes, err = KoboshPhrase.from_phrase(value)
        if err:
            self.notify(err)
            return
        self.notify("Key phrase is valid! Select a .kobosh file to decrypt.")
        self.kobosh_browser = FileBrowserWidget(
            on_submit=self.handle_kobosh_file_submit, root_path=os.getcwd()
        )
        self.mount(self.kobosh_browser)
        self.decryption_key_bytes = key_bytes

    def handle_kobosh_file_submit(self, path):
        # Only accept .kobosh files
        if not str(path).endswith(".kobosh"):
            self.notify("Please select a .kobosh file.")
            return
        # Create a Log widget for decryption
        self.log_widget = Log(id="encryption-log", highlight=True)
        self.mount(self.log_widget)
        # Extract zip to temp dir
        tmp_dir = os.path.join(os.getcwd(), "tmp_decrypt")
        if os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)
        os.makedirs(tmp_dir)
        with zipfile.ZipFile(path, "r") as zipf:
            zipf.extractall(tmp_dir)
        self.log_widget.write(f"Extracted {path} to {tmp_dir}\n")
        # Find metadata.json
        metadata_path = os.path.join(tmp_dir, "metadata.json")
        if not os.path.exists(metadata_path):
            self.log_widget.write("metadata.json not found in archive.\n")
            return
        # Decrypt metadata
        with open(metadata_path, "rb") as mf:
            nonce = mf.read(16)
            encrypted_metadata = mf.read()
        cipher = AES.new(self.decryption_key_bytes, AES.MODE_EAX, nonce=nonce)
        try:
            json_metadata = cipher.decrypt(encrypted_metadata)
            metadata = json.loads(base64.b85decode(json_metadata).decode())
        except Exception:
            self.log_widget.write("Failed to decrypt metadata.\n")
            return
        self.log_widget.write(f"Decrypted metadata: {json.dumps(metadata, indent=2)}\n")
        # Decrypt chunks
        chunk_hashes = metadata["chunks"]
        chunk_keys = metadata["keys"]
        original_name = metadata["original.name"]
        decrypted_chunks = []
        for i, chunk_hash in enumerate(chunk_hashes):
            enc_chunk_path = os.path.join(tmp_dir, chunk_hash[:12] + ".enc")
            if not os.path.exists(enc_chunk_path):
                self.log_widget.write(f"Encrypted chunk {enc_chunk_path} not found.\n")
                return
            with open(enc_chunk_path, "rb") as ef:
                nonce = ef.read(16)
                ciphertext = ef.read()
            key = base64.b85decode(chunk_keys[i])
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            try:
                chunk_data = cipher.decrypt(ciphertext)
            except Exception:
                self.log_widget.write(f"Failed to decrypt chunk {i+1}.\n")
                return
            # Verify chunk hash
            chunk_hash_actual = sha256(io.BytesIO(chunk_data))
            if chunk_hash_actual != chunk_hash:
                self.log_widget.write(
                    f"Chunk {i+1} hash mismatch! Expected {chunk_hash}, got {chunk_hash_actual}\n"
                )
                return
            chunk_out_path = os.path.join(tmp_dir, f"chunk_{i+1:02d}.dec")
            with open(chunk_out_path, "wb") as cf:
                cf.write(chunk_data)
            decrypted_chunks.append(chunk_out_path)
            self.log_widget.write(f"Decrypted and verified chunk {i+1}\n")
        # Combine chunks
        output_path = os.path.join(tmp_dir, original_name)
        with open(output_path, "wb") as outf:
            for chunk_path in decrypted_chunks:
                with open(chunk_path, "rb") as cf:
                    outf.write(cf.read())
        # Verify final file hash
        with open(output_path, "rb") as outf:
            final_hash = sha256(outf)
        if final_hash != metadata["sha256"]:
            self.log_widget.write(
                f"Final file hash mismatch! Expected {metadata['sha256']}, got {final_hash}\n"
            )
            return
        # Move file to main dir
        final_path = os.path.join(os.getcwd(), original_name)
        shutil.move(output_path, final_path)
        self.log_widget.write(f"Decryption complete! File saved as {final_path}\n")
        # Remove temp folder
        shutil.rmtree(tmp_dir)
        self.log_widget.write(f"Removed temp folder: {tmp_dir}\n")


# --- FileBrowserWidget ---


class FileBrowserWidget(Widget):

    def __init__(self, on_submit=None, root_path=None):
        super().__init__()
        self.on_submit = on_submit
        self.root_path = root_path or os.getcwd()
        self.selected_path = None

    def compose(self) -> ComposeResult:
        yield Center(
            Vertical(
                Static("Select a file to encrypt:", id="file-title"),
                DirectoryTree(self.root_path, id="file-tree"),
                id="file-box",
            ),
            id="file-center",
        )

    def on_mount(self):
        tree = self.query_one(DirectoryTree)
        tree.focus()

    def handle_intensity_submit(self, intensity):
        self.log_widget = Log(id="encryption-log", highlight=True)
        self.mount(self.log_widget)
        self.log_widget.write(f"Selected encryption intensity: {intensity}\n")
        self.log_widget.write(f"Processing file {self.file} with tmp dir {self.dir}\n")
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
            self.log_widget.write(f"Renamed {chunk} to {sha256hash}\n")
            new_chunks.append(os.path.join(root, sha256hash[:12]))
            chunkhashes.append(sha256hash)
        chunks = new_chunks.copy()
        self.log_widget.write(f"Split file into {intensity} chunks:\n")
        for chunk in chunks:
            self.log_widget.write(chunk + "\n")
        self.metadata["chunks"] = chunkhashes
        self.log_widget.write(str(self.metadata) + "\n")
        self.log_widget.write("Encrypting chunks\n")
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
                self.log_widget.write(f"Encrypted {chunk} to {encrypted_chunk_path}\n")
        self.metadata["keys"] = keys
        self.log_widget.write("Encryption complete!\n")
        self.log_widget.write("Metadata: " + json.dumps(self.metadata, indent=2) + "\n")
        zip_path = os.path.join(self.dir, f"{self.file}.kobosh")
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
        main_dir = os.getcwd()
        final_path = os.path.join(main_dir, f"{self.file}.kobosh")
        os.rename(zip_path, final_path)
        self.log_widget.write(f"Moved .kobosh file to: {final_path}\n")
        shutil.rmtree(self.dir)
        self.log_widget.write(f"Removed temp folder: {self.dir}\n")
        phrase_str = KoboshPhrase.to_phrase(bit128key)
        self.log_widget.write(f"Key phrase to decrypt metadata:\n{phrase_str}\n")

    def on_directory_tree_file_selected(self, event):
        path = event.path
        if self.on_submit:
            self.on_submit(path)
            self.remove()


if __name__ == "__main__":
    KoboshTextualApp().run()
