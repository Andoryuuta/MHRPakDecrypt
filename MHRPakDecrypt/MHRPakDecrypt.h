#pragma once


#ifdef COMPILE_DLL
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT __declspec(dllimport)
#endif


extern "C" {
	// DecryptTOCKey decrypts the 128-byte crypto key back into the 32-byte SHA3 hash key.
	DLLEXPORT void __cdecl DecryptTOCKey(unsigned char* output, unsigned char* input);
}