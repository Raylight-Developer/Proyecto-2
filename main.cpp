#include <iostream>
#include <iomanip>
#include <random>
#include <vector>

#include <windows.h>
#include <bcrypt.h>
#include <mpi.h>

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

std::vector<BCRYPT_KEY_HANDLE> generateRandomKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& amount) {
	std::vector<BCRYPT_KEY_HANDLE> keys;

	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<int> dis(0, 255);


	for (uint64_t i = 0; i < amount; ++i) {
		for (int j = 0; j < 8; ++j) {
			keyBytes[j] = static_cast<BYTE>(dis(gen));
		}
		BCRYPT_KEY_HANDLE hKey = nullptr;

		NTSTATUS status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0, keyBytes, sizeof(keyBytes), 0);
		if (status != STATUS_SUCCESS) {
			std::cerr << "BCryptGenerateSymmetricKey failed: " << status << std::endl;
			continue;
		}

		keys.push_back(hKey);
	}
	return keys;
}

std::vector<BCRYPT_KEY_HANDLE> generateOrderedKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& amount) {
	std::vector<BCRYPT_KEY_HANDLE> keys;

	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (uint64_t i = 0; i < amount; ++i) {
		for (int j = 0; j < 8; ++j) {
			keyBytes[7-j] = static_cast<BYTE>((i >> (56 - j * 8)) & 0xFF);
		}

		BCRYPT_KEY_HANDLE hKey = nullptr;

		NTSTATUS status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0, keyBytes, sizeof(keyBytes), 0);
		if (status != STATUS_SUCCESS) {
			std::cerr << "BCryptGenerateSymmetricKey failed: " << status << std::endl;
			continue;
		}

		keys.push_back(hKey);
	}
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
	BYTE keyBytes[8] = { 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
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

	std::cout << "Key: [ " << hKey << " ] | [ ";
	for (BYTE b : keyBytes) {
		printf("%02X ", b);
	}
	std::cout << "]" << std::endl;
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
	std::vector<BCRYPT_KEY_HANDLE> hKeys = generateOrderedKeys(hAlgorithm, 1024);
	for (BCRYPT_KEY_HANDLE key : hKeys) {
		if (tryKey(ciphertext, bruteDecryptedText, key)) {
			if (bruteDecryptedText == plaintext) {
				std::cout << "BruteForce Decrypted with key: [ " << hKey << " ] | [ ";
				for (BYTE b : keyBytes) {
					printf("%02X ", b);
				}
				std::cout << "] -> " << bruteDecryptedText << std::endl;
				break;
			}
		}
	}

	// Clean up
	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	return 0;
}