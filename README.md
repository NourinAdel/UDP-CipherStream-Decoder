# UDP CipherStream Decoder
### A full-stack cybersecurity simulation demonstrating the dangers of cryptographic key reuse (The Many-Time Pad Vulnerability).

---
## Overview
This is a network security project that bridges low-level network programming, cryptography, and UI development. The project consists of two systems communicating using the UDP protocol:

1. The Vulnerable Server: A backend Python script simulating a leaky server. It encrypts IT logs using a bitwise XOR cipher but makes the mistake of reusing the same cryptographic key for every packet.
2. The Cryptanalysis Client: A Tkinter-based desktop dashboard that sniffs the local network for these packets, verifies their checksums, and uses a space-detection algorithm alongside human injection to reverse-engineer the key and crack the cipher.

## Key Features
  - **UDP Protocol**: Built using Python's `socket` library, JSON packets, and checksum validation to detect data corruption over the network.
  - **Decryption Engine**: Compares intercepted ciphertexts, analyses the outputs to detect space characters (`0x20`), and derives key bytes.
  - **Interactive GUI**: Tkinter-based interface to provide user interaction. Allows users to inject plaintext guesses into specific character offsets, propagating the newly calculated key bytes across all intercepted streams.

## The Many-Time Pad Flaw
This project exploits a fundamental rule of XOR (⊕) encryption.

Normally, Plaintext ⊕ Key = Ciphertext.
However, if two different plaintexts are encrypted with the exact same key, an attacker can XOR the two resulting ciphertexts together to completely cancel out the key:
$$C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$$
By statistically analysing this combined output, we can deduce the underlying plaintexts and rebuild the key without ever needing to brute-force the encryption.

## Project Structure
```text
UDP_CipherStream_Decoder/
├── server.py
├── app.py
└── README.md
```

## Installation and Usage
No external dependencies are required.

To run the program:
1. Start the server:
```bash
python server.py
```
2. Start the client program
```bash
python app.py
```

## How to Decrypt

1. Sniff the Network
Click the "Sniff Network Traffic" button. This opens a UDP socket to capture 8 different streams from the server.
2. Identify Patterns
Examine the partially decrypted plaintexts. There will be special characters (`▒`) denoting characters that have not been decrypted yet. 
3. Inject Guesses
Use the Cryptanalysis Injection Unit at the bottom:
   - **Stream ID**: The row number (0-7) you are guessing for.
   - **Index Offset**: The numerical index (starting at 0) where the guessed word begins.
   - **Guess Word/Text**: The plaintext to be injected.
4. Observe the Result
Because the server reused the same key, decrypting a word in Stream 0 will instantly decrypt those exact same character columns for Streams 1 through 7. Continue guessing until the matrix is fully solved.
