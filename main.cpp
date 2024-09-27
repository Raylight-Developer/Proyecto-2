#include <iostream>
#include <iomanip>
#include <vector>

#include <windows.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

bool EncryptDES(const std::string& plaintext, std::vector<BYTE>& ciphertext, BCRYPT_KEY_HANDLE hKey) {
	DWORD dataLen = static_cast<DWORD>(plaintext.size());
	DWORD bufferSize = dataLen;
	ciphertext.resize(bufferSize);

	memcpy(ciphertext.data(), plaintext.data(), dataLen);

	ULONG resultSize = 0;
	if (BCryptEncrypt(hKey, (PUCHAR)ciphertext.data(), dataLen, nullptr, nullptr, 0, nullptr, 0, &resultSize, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
		std::cerr << "BCryptEncrypt (size estimation) failed." << std::endl;
		return false;
	}

	ciphertext.resize(resultSize);

	if (BCryptEncrypt(hKey, (PUCHAR)ciphertext.data(), dataLen, nullptr, nullptr, 0, ciphertext.data(), resultSize, &resultSize, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
		std::cerr << "BCryptEncrypt failed." << std::endl;
		return false;
	}

	ciphertext.resize(resultSize);
	return true;
}

bool DecryptDES(const std::vector<BYTE>& ciphertext, std::string& plaintext, BCRYPT_KEY_HANDLE hKey) {
	DWORD dataLen = static_cast<DWORD>(ciphertext.size());
	std::vector<BYTE> buffer = ciphertext;

	ULONG resultSize = 0;
	if (BCryptDecrypt(hKey, (PUCHAR)buffer.data(), dataLen, nullptr, nullptr, 0, nullptr, 0, &resultSize, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
		std::cerr << "BCryptDecrypt (size estimation) failed." << std::endl;
		return false;
	}

	buffer.resize(resultSize);

	if (BCryptDecrypt(hKey, (PUCHAR)buffer.data(), dataLen, nullptr, nullptr, 0, buffer.data(), resultSize, &resultSize, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
		std::cerr << "BCryptDecrypt failed." << std::endl;
		return false;
	}

	plaintext.assign(buffer.begin(), buffer.begin() + resultSize);
	return true;
}

bool tryKey(const std::vector<BYTE>& ciphertext, std::string& decryptedText, BCRYPT_KEY_HANDLE hKey) {
	DWORD dataLen = static_cast<DWORD>(ciphertext.size());
	std::vector<BYTE> buffer = ciphertext;

	ULONG resultSize = 0;
	if (BCryptDecrypt(hKey, (PUCHAR)buffer.data(), dataLen, nullptr, nullptr, 0, nullptr, 0, &resultSize, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
		return false;
	}

	buffer.resize(resultSize);
	if (BCryptDecrypt(hKey, (PUCHAR)buffer.data(), dataLen, nullptr, nullptr, 0, buffer.data(), resultSize, &resultSize, BCRYPT_BLOCK_PADDING) != STATUS_SUCCESS) {
		return false;
	}

	decryptedText.assign(buffer.begin(), buffer.begin() + resultSize);
	return true;
}

std::vector<BCRYPT_KEY_HANDLE> generateKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& amount) {
	std::vector<BCRYPT_KEY_HANDLE> keys;

	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (uint64_t j = 0; j < 256; ++j) {
		keyBytes[7] = static_cast<BYTE>(j);
		BCRYPT_KEY_HANDLE hKey = nullptr;

		NTSTATUS status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0, keyBytes, sizeof(keyBytes), 0);
		if (status != STATUS_SUCCESS) {
			std::cerr << "BCryptGenerateSymmetricKey failed: " << status << std::endl;
			continue;
		}

		keys.push_back(hKey);
	}
	std::cout << "Generated [" << keys.size() << "] Keys" << std::endl;

	return keys;
}

int main() {
	BCRYPT_ALG_HANDLE hAlgorithm;
	BCRYPT_KEY_HANDLE hKey;
	NTSTATUS status;

	// Step 1: Open a DES algorithm provider
	status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_DES_ALGORITHM, nullptr, 0);
	if (status != STATUS_SUCCESS) {
		std::cerr << "BCryptOpenAlgorithmProvider failed: " << status << std::endl;
		return 1;
	}

	// Step 2: Generate a symmetric key
	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25 };
	status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0, keyBytes, sizeof(keyBytes), 0);
	if (status != STATUS_SUCCESS) {
		std::cerr << "BCryptGenerateSymmetricKey failed: " << status << std::endl;
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return 1;
	}

	// Step 3: Encrypt the plaintext
	std::string plaintext = "Hello, DES Encryption!";
	std::vector<BYTE> ciphertext;
	if (!EncryptDES(plaintext, ciphertext, hKey)) {
		std::cerr << "Encryption failed" << std::endl;
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return 1;
	}

	std::cout << "Key: " << hKey << std::endl;
	std::cout << "Encrypted data: ";
	for (BYTE b : ciphertext) {
		printf("%02X ", b);
	}
	std::cout << std::endl;

	// Step 4: Decrypt the ciphertext
	std::string decryptedText;
	if (!DecryptDES(ciphertext, decryptedText, hKey)) {
		std::cerr << "Decryption failed" << std::endl;
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return 1;
	}

	std::cout << "Decrypted text: " << decryptedText << std::endl;

	// Step 5: Brute force
	std::string bruteDecryptedText;
	std::vector<BCRYPT_KEY_HANDLE> hKeys = generateKeys(hAlgorithm, 1024);
	for (BCRYPT_KEY_HANDLE key : hKeys) {
		if (tryKey(ciphertext, bruteDecryptedText, key)) {
			if (bruteDecryptedText == plaintext) {
				std::cout << "BruteForce Decrypted with key [" << key << "] -> " << bruteDecryptedText << std::endl;
				break;
			}
		}
	}

	// Clean up
	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	return 0;
}