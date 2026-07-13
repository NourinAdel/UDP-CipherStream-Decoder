import tkinter as tk
from tkinter import messagebox
import socket
import json

class udp:
    def __init__(self, ip, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((ip, port))
        self.socket.settimeout(0.5)

    def receive_packet(self):
        try:
            data, addr = self.socket.recvfrom(4096)
            return json.loads(data.decode()), addr
        except (ConnectionResetError, socket.timeout):
            return None, None

    def checksum(self, packet):
        temp = packet.copy()
        temp["checksum"] = 0
        return sum(bytearray(json.dumps(temp, sort_keys=True).encode()))

    def valid(self, packet):
        return (
                isinstance(packet, dict)
                and "checksum" in packet
                and self.checksum(packet) == packet["checksum"]
        )


class CipherDecoderGUI:
    def __init__(self, window):
        self.window = window
        self.window.title("Cryptanalysis Engine")
        self.window.geometry("800x600")

        # Data Storage
        self.ciphertexts = [None] * 8
        self.player_guesses = {}  # Map: position, computed_key_byte

        #UI Layout

        # Network Sniffer Controls
        self.network_frame = tk.LabelFrame(window, text=" Network Control Unit ", padx=10, pady=10)
        self.network_frame.pack(fill="x", padx=10, pady=5)

        self.sniff_btn = tk.Button(self.network_frame, text="Sniff Network Traffic", command=self.sniff_traffic)
        self.sniff_btn.pack(side="left", padx=5)

        self.status_label = tk.Label(self.network_frame, text="Status: Idle. Waiting for payload capture...")
        self.status_label.pack(side="left", padx=10)

        # Display matrix panel
        self.matrix_frame = tk.LabelFrame(window, text=" Intercepted Streams Matrix ", padx=10, pady=10)
        self.matrix_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Labels to hold the 8 lines of text dynamically
        self.stream_labels = []
        for i in range(8):
            lbl = tk.Label(self.matrix_frame, text=f"Stream [{i}]: Network offline.", font=("Courier", 11), anchor="w")
            lbl.pack(fill="x", pady=2)
            self.stream_labels.append(lbl)

        # Manual guess input panel
        self.guess_frame = tk.LabelFrame(window, text=" Cryptanalysis Injection Unit ", padx=10, pady=10)
        self.guess_frame.pack(fill="x", padx=10, pady=10)

        tk.Label(self.guess_frame, text="Stream ID (0-7):").grid(row=0, column=0, padx=5)
        self.stream_id_entry = tk.Entry(self.guess_frame, width=5)
        self.stream_id_entry.grid(row=0, column=1, padx=5)

        tk.Label(self.guess_frame, text="Index Offset:").grid(row=0, column=2, padx=5)
        self.offset_entry = tk.Entry(self.guess_frame, width=5)
        self.offset_entry.grid(row=0, column=3, padx=5)

        tk.Label(self.guess_frame, text="Guess Word/Text:").grid(row=0, column=4, padx=5)
        self.guess_entry = tk.Entry(self.guess_frame, width=25)
        self.guess_entry.grid(row=0, column=5, padx=5)

        self.submit_btn = tk.Button(self.guess_frame, text="Inject Guess", command=self.apply_human_guess)
        self.submit_btn.grid(row=0, column=6, padx=10)

    # Action methods

    def sniff_traffic(self):
        self.status_label.config(text="Status: Listening for packets on port 5001...")
        self.window.update()  # Forces Tkinter to redraw the UI instantly

        listener = udp('127.0.0.1', 5001)
        captured = 0

        # Loop to collect all 8 streams
        while captured < 8:
            pkt, addr = listener.receive_packet()

            if pkt and listener.valid(pkt) and pkt.get("flag") == "DATA":
                s_id = pkt.get("sentence_id")
                cipher_data = pkt.get("data")

                if 0 <= s_id < 8 and self.ciphertexts[s_id] is None:
                    self.ciphertexts[s_id] = cipher_data
                    captured = sum(1 for c in self.ciphertexts if c is not None)

                    self.status_label.config(text=f"Status: Intercepted stream {s_id} ({captured}/8)...")
                    self.window.update()

        listener.socket.close()
        self.status_label.config(text="Status: Connection closed. All 8 streams captured successfully!")
        self.run_decryption_pipeline()

    def run_decryption_pipeline(self):
        if None in self.ciphertexts:
            return

        # Convert hex representations to raw byte tracking arrays
        c_array = [bytes.fromhex(c) for c in self.ciphertexts]
        THRESHOLD = 5
        spaces_array = [[0] * len(c) for c in c_array]

        # Run automated space analysis engine
        for i in range(len(c_array) - 1):
            for j in range(i + 1, len(c_array)):
                for k in range(min(len(c_array[i]), len(c_array[j]))):
                    c_xor = c_array[i][k] ^ c_array[j][k]
                    if (0x61 <= c_xor <= 0x7A) or (0x41 <= c_xor <= 0x5A):
                        spaces_array[i][k] += 1
                        spaces_array[j][k] += 1

        # Extract key bytes matching space thresholds
        key_array = [None] * len(c_array[0])
        for i in range(len(spaces_array)):
            for j in range(len(spaces_array[i])):
                if spaces_array[i][j] >= THRESHOLD:
                    key_array[j] = c_array[i][j] ^ 0x20

        # Layer manual guesses on top of the calculated key layout
        for pos, key_byte in self.player_guesses.items():
            if pos < len(key_array):
                key_array[pos] = key_byte

        # Output plaintext strings back out to display grid
        for idx, c in enumerate(c_array):
            plaintext = []
            for i in range(len(c)):
                if i < len(key_array) and key_array[i] is not None:
                    plaintext.append(chr(c[i] ^ key_array[i]))
                else:
                    plaintext.append("▒")  # Placeholder blocks

            # Update the text of the Tkinter labels dynamically
            self.stream_labels[idx].config(text=f"Stream [{idx}]: {''.join(plaintext)}")

    def apply_human_guess(self):
        if None in self.ciphertexts:
            messagebox.showwarning("Error", "Capture data streams from the network first.")
            return

        try:
            s_id = int(self.stream_id_entry.get())
            start_pos = int(self.offset_entry.get())
            guess_text = self.guess_entry.get()

            if not (0 <= s_id < 8):
                raise ValueError
        except ValueError:
            messagebox.showerror("Invalid Input", "Ensure Stream ID is 0-7 and Offset is a valid number.")
            return

        # Core XOR key generation logic based on user string input inputs
        c_bytes = bytes.fromhex(self.ciphertexts[s_id])
        for offset, char in enumerate(guess_text):
            current_pos = start_pos + offset
            if current_pos < len(c_bytes):
                computed_key_byte = c_bytes[current_pos] ^ ord(char)
                self.player_guesses[current_pos] = computed_key_byte

        # Re-run decryption pipeline to show updates instantly
        self.run_decryption_pipeline()

        # Clear text input entries
        self.guess_entry.delete(0, tk.END)


if __name__ == "__main__":
    root = tk.Tk()
    app = CipherDecoderGUI(root)
    root.mainloop()