#pragma once

template <typename Key>
void SaveKey(const std::wstring& filename, const Key& key) {
	CryptoPP::ByteQueue queue;
	key.Save(queue);
	CryptoPP::FileSink file(filename.c_str());

	queue.CopyTo(file);
	file.MessageEnd();
}

void LoadKey(std::vector<uint8_t>& PrivKeyBytes, CryptoPP::RSA::PrivateKey& PrivKey);
BOOL SetTargetFile(std::wstring& TargetFile);
BOOL DecryptFileContent(std::wstring TargetFile, CryptoPP::RSA::PrivateKey& PrivKey);
BOOL ReadTargetFile(std::wstring TargetFile, std::vector<uint8_t>& FileContent);
BOOL WriteTargetFile(std::wstring TargetFile, std::vector<uint8_t>& FileContent);
void RSADecryptData(std::vector<uint8_t>& EncryptedData, CryptoPP::RSA::PrivateKey& PrivateKey, std::vector<uint8_t>& DecryptedData);
