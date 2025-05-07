
#include <stdio.h> // For printf
#include <Windows.h> // Windows API functions like CreateFile, MapViewOfFile
#include <stdint.h> // For fixed-width integer types like uint16_t

// Function to parse and inspect a PE (Portable Executable) file
void parsePeFile(const char* filename) {
	
	// Print file name and its pointer address (for debugging)
	printf("%s\n", filename);
	printf("%p\n", filename);


	// Open the file with read access
	HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("ERROR: Could create handle to file!");
		return;
	}

	// Create a read-only file mapping
	HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapping == INVALID_HANDLE_VALUE) {
		printf("ERROR: Could NOT create file mapping object!");
		CloseHandle(hFile);
		return;
	}


	// Map file into memory (read-only)
	LPVOID lpBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
	if (!lpBase) {
		printf("ERROR: Could NOT map view of File");

		//cleanup
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return;
	}

	// Print success message and memory address where the file is mapped
	printf("%s is mapped at address %p\n", filename, lpBase);


	// Treat the beginning of the mapped file as a DOS header (always the first structure in a PE file)
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;

	// Validate the DOS header magic number (should be 'MZ' = 0x5A4D)
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("ERROR: Invalid DOS Signature");

		//cleanup
		UnmapViewOfFile(lpBase);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return;
	}
	
	//Convert to Binary 0x5a4d = 01011010 01001101
	//Convert to Binary 0X00FF = 00000000 11111111
	// & -----------------------------------------
	//                           00000000 01001101


	// These next lines manually break down the magic number into bytes:
	// Lower byte (e.g., 0x4D)
	uint16_t lower = pDosHeader->e_magic & 0xff;

	//0x5ad >> 8 bits = 00000000 01011010
	//0X00FF          = 00000000 11111111
	// & ---------------------------------
	//                  00000000 01011010


	// Upper byte (e.g., 0x5A)
	uint16_t upper = (pDosHeader->e_magic >> 8) & 0xff;

	// Print the two magic bytes as hex (e.g., 0x4D5A or 0x5A4D depending on order)
	printf("Magic Bytes: 0x%x%x\n", lower, upper);

	// Print the magic bytes as characters ('MZ' = '4D 5A')
	printf("Magic Bytes: %c%c\n", lower, upper);


	printf("Offset to NT Headers: 0x%x\n", pDosHeader->e_lfanew);
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS) ((BYTE*)lpBase + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("ERROR: Not a valid NT PE Signature!");
		// Clean up memory mappings and file handles
		UnmapViewOfFile(lpBase);
		CloseHandle(hMapping);
		CloseHandle(hFile);
		return;
	}

	// Print NT header address, number of sections, and entry point
	printf("Address to beginning of NT Headers: 0x%p\n", pNtHeaders);
	printf("Number of Sections: %d\n", pNtHeaders->FileHeader.NumberOfSections);
	printf("Entry Point: 0x%x\n", pNtHeaders->OptionalHeader.AddressOfEntryPoint);



	// Wait for user input so the console window doesn't close immediately
	getchar();

	// Clean up memory mappings and file handles
	UnmapViewOfFile(lpBase);
	CloseHandle(hMapping);
	CloseHandle(hFile);

}

// Program entry point
int main()
{
	// Test your function on notepad.exe (valid Windows PE file)
	parsePeFile("C:\\Windows\\System32\\notepad.exe");

	return 0;
}