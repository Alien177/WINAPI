#include "pch.h"
#include "Helper.h"

BOOL bCreateKey = FALSE;
CryptoPP::RSA::PrivateKey RSAPrivKey;
std::wstring TargetFile;

std::vector<uint8_t> PrivateKeyBytes = { 0x30, 0x82, 0x04, 0xBC, 0x02, 0x01, 0x00, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x04, 0x82, 0x04, 0xA6, 0x30, 0x82, 0x04, 0xA2, 0x02, 0x01, 0x00, 0x02, 0x82, 0x01, 0x01, 0x00, 0x99, 0x8F, 0xC2, 0x95, 0x34, 0x81, 0x4B, 0x56, 0x50, 0xED, 0xB3, 0x4D, 0x06, 0xF2, 0x7B, 0xFF, 0x64, 0x01, 0x7F, 0xB8, 0x55, 0x6F, 0xBD, 0xC2, 0xEA, 0x12, 0x6B, 0x69, 0xD4, 0x6F, 0x5B, 0x12, 0x58, 0x5E, 0x4D, 0xA9, 0x5B, 0xB9, 0x39, 0xFC, 0x34, 0xB9, 0xDE, 0x67, 0xFB, 0xF3, 0xDC, 0x8E, 0x29, 0xB3, 0xC4, 0xC1, 0x71, 0x4E, 0x07, 0x4B, 0xCE, 0x0D, 0x29, 0x40, 0xCC, 0xA3, 0xE8, 0xF5, 0xEA, 0x0E, 0x78, 0x36, 0xDA, 0x56, 0xB3, 0x6E, 0x78, 0xEC, 0x95, 0x64, 0x17, 0x34, 0xBB, 0xE2, 0x9C, 0x2F, 0x56, 0x17, 0xFF, 0x31, 0x4E, 0x6E, 0xFE, 0x93, 0x33, 0x1F, 0xCA, 0x80, 0xA8, 0xC1, 0xED, 0x55, 0x82, 0xEB, 0x6A, 0x14, 0xED, 0x08, 0xEA, 0x12, 0x9C, 0x30, 0xEB, 0xFD, 0x47, 0x6C, 0x71, 0x66, 0x2A, 0x6F, 0xF6, 0x1F, 0x59, 0x05, 0xDD, 0x52, 0x68, 0x34, 0x64, 0x35, 0xCA, 0xF1, 0x12, 0x18, 0xCA, 0x4D, 0x77, 0x8B, 0x56, 0x26, 0xC9, 0x2B, 0x0D, 0x1B, 0x6B, 0x95, 0xE2, 0xB7, 0xD5, 0x13, 0xCC, 0x92, 0x16, 0x5D, 0x5D, 0xE9, 0x6F, 0xFD, 0x22, 0x0F, 0x40, 0xAB, 0x96, 0xF5, 0x0D, 0x19, 0x4F, 0x24, 0x0A, 0x5D, 0x7D, 0xCC, 0xB8, 0x4E, 0x8F, 0x8D, 0x75, 0x9E, 0x7A, 0xA0, 0x80, 0xD5, 0x8E, 0x2F, 0x70, 0xE2, 0xF5, 0xFB, 0x2D, 0x79, 0x99, 0x56, 0xE0, 0xC2, 0xD4, 0xA8, 0xF1, 0x7B, 0x06, 0xC0, 0x7B, 0xBF, 0x8C, 0x8D, 0xA4, 0xF8, 0xF9, 0x63, 0xFA, 0x56, 0x43, 0x5C, 0x64, 0xCF, 0x95, 0x08, 0xA4, 0x6C, 0x14, 0x02, 0xD6, 0x5E, 0x81, 0x1B, 0xC2, 0x51, 0xC3, 0x89, 0x93, 0x5D, 0xAC, 0xAE, 0xF5, 0xA7, 0xD1, 0xDC, 0xE4, 0x81, 0x17, 0xC9, 0x75, 0x88, 0xCD, 0x0F, 0xF8, 0x9C, 0x2E, 0x4D, 0xE4, 0x59, 0x41, 0x2A, 0xBE, 0x4D, 0x1D, 0x92, 0x1E, 0x53, 0xD9, 0x95, 0x02, 0x01, 0x11, 0x02, 0x82, 0x01, 0x00, 0x1B, 0x19, 0x5E, 0x92, 0xCD, 0x07, 0xC2, 0x00, 0x2C, 0x66, 0x2E, 0xB3, 0x3D, 0x76, 0x15, 0xE1, 0xC6, 0x5A, 0x9E, 0x11, 0x78, 0x7D, 0x21, 0x7C, 0xBF, 0xE5, 0x22, 0x03, 0x9D, 0xF5, 0x88, 0x8A, 0xC4, 0x4C, 0xE0, 0x87, 0x4C, 0x6B, 0xFB, 0x2C, 0x81, 0xC6, 0x72, 0x8A, 0xD2, 0x1B, 0xF9, 0xBE, 0xBC, 0x10, 0xAA, 0x40, 0x41, 0x2B, 0xE3, 0x2B, 0x7E, 0xB7, 0x07, 0x47, 0xAB, 0xA4, 0x74, 0x67, 0xA1, 0xC6, 0x51, 0x73, 0x17, 0x78, 0xB6, 0x40, 0xAB, 0xED, 0x83, 0xC6, 0x5E, 0x72, 0xB7, 0xBE, 0x94, 0x08, 0x5A, 0x7C, 0xB4, 0x90, 0x3B, 0x04, 0x87, 0x47, 0x27, 0x23, 0xBA, 0x52, 0xF0, 0x9A, 0xB1, 0x69, 0x71, 0x74, 0xD6, 0x7C, 0x29, 0xD4, 0x65, 0x8A, 0xD0, 0x44, 0xDE, 0x59, 0xDF, 0x6D, 0x7D, 0x6C, 0x61, 0xD7, 0x85, 0xC9, 0x4B, 0xF1, 0xF9, 0xE1, 0x5D, 0xAE, 0xE4, 0x81, 0xF6, 0xA2, 0xBD, 0x24, 0x65, 0x42, 0xC7, 0x2E, 0xFB, 0x3F, 0xE6, 0x8F, 0xAE, 0x1E, 0xD5, 0x52, 0x8D, 0x0B, 0x98, 0x8C, 0xC3, 0x68, 0x2A, 0x06, 0xF4, 0xE2, 0x0D, 0x59, 0xFA, 0xDA, 0x5D, 0x1E, 0x5B, 0x2F, 0x4B, 0xED, 0x5C, 0x31, 0x09, 0xAF, 0xDC, 0x11, 0xB5, 0x77, 0x01, 0x72, 0x74, 0x08, 0x25, 0x72, 0xA4, 0x15, 0xA3, 0xEB, 0x7B, 0xE0, 0x3E, 0x33, 0x1E, 0x0F, 0xEE, 0xC3, 0x44, 0xAD, 0xBB, 0xA1, 0xAB, 0x73, 0x97, 0x5B, 0x31, 0x58, 0xA0, 0x35, 0x4C, 0x76, 0x5A, 0xDF, 0xBC, 0x3E, 0xE2, 0xA7, 0x80, 0x9E, 0xB7, 0x31, 0x2F, 0x1D, 0x97, 0xE8, 0xD0, 0x14, 0xBF, 0xCC, 0xE4, 0x7D, 0x02, 0x17, 0xE6, 0xAE, 0xCD, 0xC6, 0x5E, 0xCD, 0x2F, 0xD5, 0xDF, 0x62, 0x0B, 0xE7, 0x43, 0x15, 0x39, 0x8F, 0xEC, 0x52, 0xCD, 0x62, 0x25, 0x2F, 0x57, 0x0D, 0xBD, 0x21, 0x39, 0x11, 0x8E, 0x33, 0x68, 0x51, 0x02, 0x81, 0x81, 0x00, 0xCF, 0x8A, 0x98, 0xBF, 0x7D, 0xD7, 0x6C, 0xD6, 0x12, 0x1D, 0x93, 0xE2, 0x0E, 0x14, 0xD2, 0xBB, 0xFA, 0xA6, 0x51, 0x2C, 0xC2, 0x2C, 0x9E, 0x60, 0xBF, 0x76, 0xEA, 0x0C, 0x6F, 0xB4, 0x78, 0x3C, 0x9B, 0xD9, 0x2A, 0xB3, 0x2D, 0x39, 0x08, 0x3D, 0x1C, 0xED, 0x51, 0x81, 0x34, 0xE7, 0x06, 0x08, 0x8A, 0x07, 0xFA, 0x04, 0x48, 0xD6, 0xDF, 0x90, 0x72, 0x63, 0x9A, 0x2F, 0x4A, 0xBF, 0x4D, 0x62, 0xB7, 0x85, 0xAD, 0x2E, 0x69, 0xDF, 0x03, 0xB1, 0x99, 0x00, 0x94, 0x95, 0x7E, 0x91, 0x16, 0x8E, 0x47, 0x61, 0xE5, 0x92, 0xBC, 0xAE, 0xF2, 0xC4, 0x55, 0x3A, 0x2C, 0xC2, 0x48, 0x47, 0x8D, 0xED, 0x6B, 0x99, 0xF2, 0xFA, 0x1F, 0xCE, 0x6E, 0x13, 0x77, 0x65, 0x13, 0x82, 0x48, 0x4A, 0xE9, 0x87, 0x43, 0xD6, 0xE5, 0x4E, 0x04, 0x82, 0x15, 0xFD, 0x9B, 0x5C, 0x54, 0x73, 0x30, 0x07, 0x14, 0xB9, 0x02, 0x81, 0x81, 0x00, 0xBD, 0x6A, 0x9E, 0x68, 0xE6, 0x54, 0x59, 0x91, 0x47, 0x34, 0x9E, 0x8A, 0xA4, 0xAD, 0x46, 0x0F, 0x79, 0xFA, 0x7D, 0x6C, 0x66, 0x09, 0x53, 0xDD, 0x0F, 0x88, 0x55, 0x2D, 0x6B, 0xF5, 0xC4, 0xAC, 0x6D, 0xA9, 0xC4, 0xB0, 0x50, 0xEA, 0x96, 0x80, 0x97, 0x14, 0x35, 0xD9, 0x04, 0x89, 0x4B, 0x0E, 0x54, 0xFD, 0x9D, 0xF4, 0xBF, 0x6A, 0xB5, 0xF3, 0xBB, 0x66, 0x60, 0xD5, 0x10, 0xD5, 0xB5, 0x5C, 0xC3, 0xBB, 0xAA, 0x8D, 0x4F, 0x94, 0xFD, 0x03, 0x5A, 0xAF, 0x0C, 0x85, 0x51, 0x0B, 0x7D, 0xC3, 0x99, 0xEA, 0x4C, 0x09, 0xDC, 0xC0, 0x19, 0xC1, 0xE6, 0x04, 0x15, 0x7B, 0x15, 0xF0, 0x7F, 0x14, 0xB7, 0x3A, 0x80, 0xFB, 0x67, 0x4E, 0xAA, 0x0D, 0x7B, 0x45, 0xC0, 0xD3, 0x5B, 0xC5, 0x9D, 0x59, 0x24, 0x45, 0x67, 0xD3, 0xB7, 0xCA, 0xE8, 0x89, 0xF3, 0x34, 0x85, 0xBB, 0x73, 0x29, 0x75, 0xBD, 0x02, 0x81, 0x80, 0x7A, 0x15, 0x4A, 0xCA, 0xFE, 0xBA, 0xF4, 0xBA, 0x28, 0xC6, 0x1A, 0xC1, 0x35, 0x75, 0xA9, 0x23, 0x48, 0x25, 0x99, 0x29, 0x63, 0x29, 0x4E, 0x1A, 0xCA, 0xFA, 0xA7, 0xCB, 0x14, 0x88, 0x46, 0xBA, 0x3D, 0x8E, 0xCD, 0xD2, 0xCF, 0x4E, 0xB9, 0x8D, 0x5C, 0x4F, 0x5D, 0x1E, 0xD3, 0xD3, 0x30, 0xB9, 0xBA, 0x9B, 0x47, 0xC6, 0x48, 0xF6, 0xDD, 0xDC, 0x7F, 0x85, 0xE2, 0x39, 0xEF, 0xBB, 0xD3, 0x2B, 0x02, 0x8A, 0xDE, 0x57, 0x89, 0x92, 0x3E, 0x68, 0x78, 0x1E, 0x75, 0x85, 0x1D, 0x46, 0x49, 0x80, 0xDE, 0xB2, 0x0E, 0x92, 0x8D, 0x1B, 0x9D, 0xDC, 0xE6, 0xD6, 0xED, 0x26, 0xFD, 0x57, 0x44, 0x6D, 0x8A, 0x96, 0xCB, 0x29, 0xB8, 0x5B, 0x4F, 0xCF, 0x37, 0x2C, 0x65, 0xD4, 0x2A, 0x86, 0x6B, 0x40, 0x82, 0x42, 0x2C, 0x88, 0x3E, 0xE3, 0x1B, 0xFE, 0x97, 0x9F, 0xB9, 0x34, 0xB2, 0xD6, 0xFD, 0x21, 0x02, 0x81, 0x81, 0x00, 0xA7, 0x21, 0xD7, 0x11, 0x43, 0xB3, 0xD6, 0x8F, 0x3E, 0xD4, 0x13, 0x6B, 0x46, 0x02, 0x4C, 0xE0, 0x7A, 0xAF, 0xD8, 0x14, 0x5A, 0x08, 0x3A, 0xF0, 0x3A, 0xE1, 0xB4, 0x91, 0x7D, 0x60, 0x62, 0x3D, 0xCA, 0x2C, 0x62, 0x41, 0x38, 0x56, 0x84, 0xCB, 0xD0, 0x99, 0x5C, 0xB0, 0x6D, 0x6A, 0x15, 0x0C, 0xA5, 0x58, 0x40, 0x14, 0x30, 0x6D, 0x37, 0x22, 0x5A, 0x0F, 0x0A, 0x25, 0x69, 0x35, 0x09, 0x6F, 0xF7, 0xFF, 0xF0, 0xD7, 0x09, 0xFB, 0xEE, 0x4E, 0x40, 0xF4, 0xCE, 0xCF, 0xFC, 0x37, 0x50, 0xD9, 0xC4, 0x0A, 0xF7, 0xCC, 0x77, 0x7C, 0x52, 0xF6, 0x61, 0x8B, 0x22, 0x03, 0x31, 0x79, 0xD9, 0x8A, 0xBF, 0xCA, 0x35, 0x92, 0x88, 0x54, 0x77, 0xED, 0xC7, 0x1F, 0x6D, 0xE7, 0xAB, 0x54, 0x03, 0x4E, 0xA7, 0x88, 0x88, 0xC9, 0xDE, 0x67, 0xBE, 0x1F, 0x5E, 0x1F, 0x48, 0xD2, 0x92, 0xCA, 0x3A, 0xB5, 0x02, 0x81, 0x81, 0x00, 0x9F, 0x4F, 0x98, 0x02, 0x39, 0x87, 0xD6, 0x98, 0x69, 0xAA, 0x10, 0xE4, 0x77, 0x42, 0x07, 0x2B, 0x05, 0x15, 0xB5, 0x74, 0xAE, 0x5B, 0x65, 0xA2, 0x99, 0x80, 0x9B, 0xA9, 0x79, 0xFC, 0xFF, 0xFA, 0x25, 0x04, 0xB1, 0xC4, 0x04, 0x1D, 0x75, 0x73, 0x23, 0x78, 0xEC, 0x35, 0x86, 0xD9, 0x32, 0x05, 0x11, 0x4C, 0x72, 0x04, 0xC8, 0xD9, 0x3A, 0x06, 0xF2, 0xFD, 0xB1, 0x25, 0x9C, 0xDB, 0xC8, 0x75, 0x76, 0x23, 0x90, 0xD3, 0xCC, 0xB9, 0xA9, 0x27, 0xD7, 0xBB, 0x75, 0x95, 0x7A, 0xDA, 0xDB, 0xAB, 0xFB, 0xAC, 0x4F, 0xBB, 0xD8, 0x26, 0xD0, 0xD4, 0x8B, 0xD0, 0xE9, 0xC9, 0xDE, 0x3E, 0x80, 0x29, 0xF7, 0x6A, 0xCE, 0x96, 0x01, 0xDE, 0xD6, 0xAA, 0x11, 0x9B, 0xF6, 0xF5, 0xF2, 0x7A, 0x0C, 0xF0, 0xDE, 0xB6, 0xBE, 0xAB, 0x81, 0xD3, 0x86, 0x64, 0xF7, 0x75, 0x3D, 0xF8, 0x3C, 0x09, 0xE1, 0xB2 };

int main(int argc, wchar_t* argv) {

	if (bCreateKey) {
		
		size_t KeyLength = 2048;
		std::wstring publicKeyFile = L"pub.key";
		std::wstring privateKeyFile = L"priv.key";

		CryptoPP::AutoSeededRandomPool prng;
		CryptoPP::InvertibleRSAFunction parameters;
		parameters.GenerateRandomWithKeySize(prng, KeyLength);

		CryptoPP::RSA::PublicKey publicKey(parameters);
		CryptoPP::RSA::PrivateKey privateKey(parameters);

		SaveKey(publicKeyFile, publicKey);
		SaveKey(privateKeyFile, privateKey);
	}

	if (!SetTargetFile(TargetFile)) {
		printf("Execution: Decryptor.exe path_to_file\n");
		return 1;
	}

	LoadKey(PrivateKeyBytes, RSAPrivKey);

	if (!DecryptFileContent(TargetFile, RSAPrivKey)) {
		return 1;
	}

	return 0;
}