#include "Crypt.hpp"

/**
 * @brief Encrypts a plaintext message using DES encryption.
 * 
 * @param plaintext The string containing the plaintext message to be encrypted.
 * @param ciphertext A vector of BYTEs that will hold the resulting encrypted message.
 * @param hKey The DES key handle used for encryption.
 * @return true if encryption was successful, false otherwise.
 */
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

/**
 * @brief Decrypts a DES encrypted ciphertext message.
 * 
 * @param ciphertext A vector of BYTEs containing the encrypted message.
 * @param plaintext The string that will hold the resulting decrypted message.
 * @param hKey The DES key handle used for decryption.
 * @return true if decryption was successful, false otherwise.
 */
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

/**
 * @brief Attempts to decrypt the ciphertext using the provided DES key and checks if the result matches an expected value.
 * 
 * @param ciphertext A vector of BYTEs containing the encrypted message.
 * @param decryptedText The string that will hold the resulting decrypted message if the key is correct.
 * @param hKey The DES key handle to try for decryption.
 * @return true if the decryption is successful and matches the expected value, false otherwise.
 */
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

BCRYPT_KEY_HANDLE generateAscendingKey(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& i) {
	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (uint64_t j = 0; j < 8; ++j) {
		keyBytes[7 - j] = static_cast<BYTE>((i >> (56 - j * 8)) & 0xFF);
	}

	BCRYPT_KEY_HANDLE hKey = nullptr;

	NTSTATUS status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0, keyBytes, sizeof(keyBytes), 0);
	if (status != STATUS_SUCCESS) {
		std::cerr << "BCryptGenerateSymmetricKey failed: " << status << std::endl;
		return nullptr;
	}

	return hKey;
}

BCRYPT_KEY_HANDLE generateDescendingKey(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& i) {
	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (uint64_t j = 0; j < 8; ++j) {
		keyBytes[7 - j] = (static_cast<BYTE>((std::numeric_limits<uint64_t>::max() - i) >> (56 - j * 8)) & 0xFF);
	}

	BCRYPT_KEY_HANDLE hKey = nullptr;

	NTSTATUS status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0, keyBytes, sizeof(keyBytes), 0);
	if (status != STATUS_SUCCESS) {
		std::cerr << "BCryptGenerateSymmetricKey failed: " << status << std::endl;
		return nullptr;
	}

	return hKey;
}

BCRYPT_KEY_HANDLE generateRandomKey(BCRYPT_ALG_HANDLE hAlgorithm) {
	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<int> dis(0, 255);

	for (int j = 0; j < 8; ++j) {
		keyBytes[j] = static_cast<BYTE>(dis(gen));
	}
	BCRYPT_KEY_HANDLE hKey = nullptr;

	NTSTATUS status = BCryptGenerateSymmetricKey(hAlgorithm, &hKey, nullptr, 0, keyBytes, sizeof(keyBytes), 0);
	if (status != STATUS_SUCCESS) {
		std::cerr << "BCryptGenerateSymmetricKey failed: " << status << std::endl;
		return nullptr;
	}

	return hKey;
}

BCRYPT_KEY_HANDLE generateKey(BCRYPT_ALG_HANDLE hAlgorithm, uint64_t& i, const uint8_t mode) {
	switch (mode) {
		case 0:
			return generateAscendingKey(hAlgorithm, i);
		case 1:
			return generateDescendingKey(hAlgorithm, i);
		case 2:
			return generateRandomKey(hAlgorithm);
	}
	return generateAscendingKey(hAlgorithm, i);
}