#include "Crypt.hpp"

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

std::vector<BCRYPT_KEY_HANDLE> generateRandomKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end) {
	std::vector<BCRYPT_KEY_HANDLE> keys;

	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<int> dis(0, 255);


	for (uint64_t i = start; i < end; ++i) {
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

std::vector<BCRYPT_KEY_HANDLE> generateAscendingKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end) {
	std::vector<BCRYPT_KEY_HANDLE> keys;

	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (uint64_t i = start; i < end; ++i) {
		for (uint64_t j = 0; j < 8; ++j) {
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

std::vector<BCRYPT_KEY_HANDLE> generateDescendingKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end) {
	std::vector<BCRYPT_KEY_HANDLE> keys;

	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (uint64_t i = std::numeric_limits<uint64_t>::max() - start; i > std::numeric_limits<uint64_t>::max() - end; --i) {
		for (uint64_t j = 0; j < 8; ++j) {
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

std::vector<BCRYPT_KEY_HANDLE> generateSteppedKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end, const uint64_t steps)
{
	std::vector<BCRYPT_KEY_HANDLE> keys;

	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (uint64_t i = start; i < end; i += steps) {
		for (uint64_t j = 0; j < 8; ++j) {
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
