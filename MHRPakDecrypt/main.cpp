#include "MHRPakDecrypt.h"

// Internal raw-assembly decryption function.
extern "C" void _transform_crypto_key(unsigned char* output, unsigned char* input128);


extern "C" {
	// DecryptTOCKey decrypts the 128-byte crypto key back into the 32-byte SHA3 hash key.
	DLLEXPORT void __cdecl DecryptTOCKey(unsigned char* output, unsigned char* input) {
		_transform_crypto_key(output, input);
	}
}

