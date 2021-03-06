# MHRPakDecrypt
Isolated functionality from MHR to decrypt the .pak TOC crypo buffer (128 bytes).

You can consume/call the DLL like such:
```cpp

// DecryptTOCKey decrypts the 128-byte crypto key back into the 32-byte SHA3 hash key.
typedef void (*__cdecl DecryptTOCKey_t)(unsigned char* output, unsigned char* input);
auto hDll = LoadLibraryA("MHRPakDecrypt.dll");
auto DecryptTOCKey = reinterpret_cast<DecryptTOCKey_t>(GetProcAddress(hDll, "DecryptTOCKey"));

// The 128 bytes following the encrypted TOC in the .pak.
unsigned char input_key[128] = {
    0x46, 0x6D, 0x41, 0x57, 0x76, 0xFD, 0x71, 0x2C, 0xC7, 0x1A, 0x12, 0xE7, 0x68, 0x81, 0x7B, 0xF6,
    0x8D, 0xE7, 0x36, 0x1F, 0x27, 0x89, 0x45, 0x16, 0xD7, 0x7E, 0x95, 0x7A, 0x35, 0x02, 0x39, 0x73,
    0xD5, 0x3C, 0xE0, 0x82, 0x39, 0xF6, 0x28, 0xD5, 0x5B, 0x1C, 0x07, 0xF6, 0x41, 0x5D, 0xCD, 0x3C,
    0xD6, 0x1D, 0x1A, 0x00, 0x24, 0xFF, 0xCD, 0x2B, 0x2E, 0x50, 0xBA, 0x5C, 0x0C, 0xAA, 0x4C, 0xF5,
    0x98, 0x3A, 0x7D, 0x89, 0x2C, 0xDC, 0x63, 0x3E, 0x8E, 0x3F, 0x54, 0xFF, 0xE4, 0xF6, 0x76, 0x51,
    0x4B, 0xCD, 0x16, 0x9F, 0xF3, 0x7D, 0x05, 0x65, 0xBF, 0xED, 0xC1, 0xC1, 0x07, 0x47, 0xC2, 0x66,
    0x42, 0x2B, 0x49, 0x35, 0x34, 0x5C, 0x9A, 0xAC, 0x39, 0x38, 0x0D, 0xE9, 0xDA, 0x12, 0x68, 0x92,
    0x49, 0xFD, 0xED, 0x28, 0x37, 0x71, 0x06, 0xE1, 0xBA, 0x41, 0xB8, 0xB6, 0xF5, 0x1C, 0x31, 0x50};

// Both the input and output should be 128-byte buffers,
// regardless of the output only being in the first 32 bytes.
unsigned char output[128] = { 0 };
DecryptTOCKey(output, input_key);

// The first 32 bytes of output now contain the SHA3 hash used to encrypt the .pak TOC.
```