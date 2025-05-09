# Shellcode64: A 64-bit Reverse Shell in Assembly

## Description
This repository contains a **64-bit reverse shell** implemented in Assembly, designed for educational and research purposes. The shellcode is optimized to be called from C++ code. 

The project demonstrates how to craft a reverse shell manually using Assembly, making it an excellent resource for learning low-level programming, shellcoding, and security concepts.

This custom shellcode helps evade antivirus and EDR solutions because it is a custom payload, not generated by tools like msfvenom or using publicly available ones. Creating your own custom shellcode adds an additional layer of evasion.

---

## Features
- A **64-bit reverse shell** written in Assembly.
- Fully functional example shellcode.
- Designed to be embedded and executed from a C++ host application.
- Customizable IP address and port settings (default port: **4444**).
---

## Usage

### Step 1: Clone the Repository
```bash
git clone https://github.com/<your-username>/shellcode64.git
cd shellcode64
```

### Step 2: Update the IP and Port
Open the project in Visual Studio, and open `shellcode.asm`.
At line 159 the value `0a64a8c05c11` represents the **IP address** and **port number** encoded in the shellcode. Here’s a detailed breakdown of how it was assembled.

- **`0a64a8c0`**: Represents the IP address.
- **`5c11`**: Represents the port number.

The IP address is encoded as a 32-bit hexadecimal value, where each byte corresponds to one octet of the address, stored in little-endian.

1. Split `0a64a8c0` into four bytes:
   - `0a` = 10  
   - `64` = 100  
   - `a8` = 168  
   - `c0` = 192  

2. Combine these values in reverse (little-endian) to form the dotted-decimal IP format:
192.168.100.10

The port number is encoded as a 16-bit hexadecimal value, also stored in little-endian.

`115C` corresponds to the decimal value `4444` which is the port.

because of little-endian format, you to reverse it in assembly code.

And now you can compile & run the code 

---

## Reference

If you want to follow a more technical in depth step by step of the assembly part this is a reference:

https://g3tsyst3m.github.io/shellcoding/assembly/debugging/x64-Assembly-and-Shellcoding-101/
