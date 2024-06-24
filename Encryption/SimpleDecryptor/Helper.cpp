#include "pch.h"
#include "Helper.h"

BOOL DecryptFileContent(std::wstring TargetFile, CryptoPP::RSA::PrivateKey& PrivKey)
{
	std::vector<uint8_t> fileContent;
	
	// Read encrypted data
	if (!ReadTargetFile(TargetFile, fileContent)) {
		return FALSE;
	}

	if (fileContent.empty()) { return TRUE; }

	std::vector<uint8_t> encryptedChaCha20(fileContent.end() - 256, fileContent.end());
	std::vector<uint8_t> encyptedFileContent(fileContent.begin(), fileContent.end() - 256);

	std::vector<uint8_t> decryptedChaCha20;
	RSADecryptData(encryptedChaCha20, PrivKey, decryptedChaCha20);
	std::vector<uint8_t> ChaCha20Key(decryptedChaCha20.begin(), decryptedChaCha20.begin() + 32);
	std::vector<uint8_t> ChaCha20IV(decryptedChaCha20.begin() + 32, decryptedChaCha20.end());

	CryptoPP::ChaCha::Decryption dec;
	dec.SetKeyWithIV(ChaCha20Key.data(), ChaCha20Key.size(), ChaCha20IV.data(), ChaCha20IV.size());

	std::vector<uint8_t> decryptedFileContent(encyptedFileContent.size());
	dec.ProcessData(decryptedFileContent.data(), encyptedFileContent.data(), encyptedFileContent.size());
	
	if (!WriteTargetFile(TargetFile, decryptedFileContent)) {
		return FALSE;
	}
  
	size_t lastindex = TargetFile.find_last_of(L".");
	std::wstring rawname = TargetFile.substr(0, lastindex);

	std::wstring TargetFileEncrypted = rawname + L".decrypted";
	if (!MoveFileW(TargetFile.data(), TargetFileEncrypted.data())) {
		return FALSE;
	}

	return TRUE;
}

void LoadKey(std::vector<uint8_t>& PrivKeyBytes, CryptoPP::RSA::PrivateKey& PrivKey) {
	CryptoPP::ByteQueue queue;
	CryptoPP::VectorSource RSA(PrivKeyBytes, true);
	RSA.TransferTo(queue);
	queue.MessageEnd();
	PrivKey.Load(queue);
}

BOOL SetTargetFile(std::wstring& TargetFile)
{
	std::wstring commandline = GetCommandLineW();
	if (!commandline.data()) {
		printf("[-] GetCommandLineW failed: %d\n", GetLastError());
		return FALSE;
	}

	int argc = 0;
	LPWSTR* argv;

	argv = CommandLineToArgvW(commandline.data(), &argc);

	if (argc != 2) {
		return FALSE;
	}

	TargetFile = argv[1];
	return TRUE;
}

BOOL ReadTargetFile(std::wstring TargetFile, std::vector<uint8_t>& FileContent)
{
	HANDLE hFile;
	DWORD dwBytesRead = 0;
	DWORD dwFileSize = 0;
	OVERLAPPED ol = { 0 };

	hFile = CreateFileW(TargetFile.data(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW failed.\n");
		return FALSE;
	}

	dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == 0) {
		printf("[-] GetFileSize failed.\n");
		CloseHandle(hFile);
		return FALSE;
	}

	FileContent.resize(dwFileSize);

	if (!ReadFileEx(hFile, FileContent.data(), dwFileSize, &ol, NULL)) {
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

BOOL WriteTargetFile(std::wstring TargetFile, std::vector<uint8_t>& FileContent)
{
	HANDLE hFile;
	DWORD dwBytesWritten = 0;
	OVERLAPPED ol = { 0 };

	hFile = CreateFileW(TargetFile.data(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW failed.\n");
		return FALSE;
	}

	if (!WriteFile(hFile, FileContent.data(), FileContent.size(), &dwBytesWritten, NULL)) {
		printf("[-] WriteFile failed.\n");
		return FALSE;
	}

	CloseHandle(hFile);
	return TRUE;
}

void RSADecryptData(std::vector<uint8_t>& EncryptedData, CryptoPP::RSA::PrivateKey& PrivateKey, std::vector<uint8_t>& DecryptedData)
{
	CryptoPP::RSAES_OAEP_SHA256_Decryptor RSADecryptor(PrivateKey);
	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::VectorSource(EncryptedData, true, new CryptoPP::PK_DecryptorFilter(prng, RSADecryptor, new CryptoPP::VectorSink(DecryptedData)));
}
