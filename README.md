# 📦 Windows-PE-Header-Parser

A simple C program that parses and prints basic information from a Windows Portable Executable (PE) file such as `notepad.exe`. It inspects the DOS and NT headers to reveal useful metadata like the magic bytes, NT header offset, number of sections, and the entry point address.

---

## 🧠 What It Does

This program:
- Opens and memory maps a `.exe` file using Windows API
- Validates the **DOS signature** (`MZ`)
- Retrieves and displays:
  - Magic bytes (in both hex and ASCII)
  - Offset to NT headers
  - Number of sections in the PE file
  - Entry point address of the executable

---

## 🪄 What Are "Magic Bytes"?

**Magic bytes** are the first few bytes of a file used to identify its format.

For PE (Portable Executable) files:
- **Hex:** `0x5A4D`
- **ASCII:** `'MZ'`

The initials “MZ” refer to **Mark Zbikowski**, one of the original developers of the MS-DOS executable format. These bytes are located at the very beginning of the file and are checked to ensure it's a valid PE file.

---

## 📊 Example Output

```text
C:\Windows\System32\notepad.exe
0x00007ff609d76190
C:\Windows\System32\notepad.exe is mapped at address 0000023278D00000
Magic Bytes: 0x4d5a
Magic Bytes: MZ
Offset to NT Headers: 0xf8
Address to beginning of NT Headers: 0x0000023278D000F8
Number of Sections: 7
Entry Point: 0x12e60
```

### 🖼️ Screenshot
Below is a sample output when parsing `notepad.exe`: PE Header Parser Output ![image](https://github.com/user-attachments/assets/d41381f9-068f-44c6-8ae5-b05f33136084)

