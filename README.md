# Windows-PE-Header-Parser

This project is a simple C program that analyzes Windows Portable Executable (PE) files by reading and parsing their headers. It maps a PE file into memory and extracts key information such as the DOS header, NT headers, section table, and entry point.

### 🔍 Features:
- Validates DOS (`MZ`) and NT (`PE\0\0`) signatures
- Extracts and prints:
  - Magic bytes (`MZ`)
  - Offset to NT headers
  - Number of sections
  - Entry point address
- Uses memory-mapped file I/O for efficiency
- Clean error handling and memory cleanup

### 🛠️ Requirements:
- Windows OS
- Windows SDK (for `<Windows.h>`)

### 🖼️ Screenshot
Below is a sample output when parsing `notepad.exe`: PE Header Parser Output(https://github.com/user-attachments/assets/27a1b083-f97f-4dd0-8e2b-604b83aaa93f)
