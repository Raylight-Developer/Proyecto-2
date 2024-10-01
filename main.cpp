#include <iostream>
#include <iomanip>
#include <random>
#include <vector>
#include <chrono>
#include <string>

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

std::vector<BCRYPT_KEY_HANDLE> generateOrderedKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end) {
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

int main(int argc, char** argv) {
	bool parallel = false;
	bool sequential = false;
	bool random_keys = false;
	uint64_t key_count = 1024 * 1024;
	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--parallel") == 0 && i + 1 < argc) {
			parallel = argv[++i] == "true" ? true : false;
		} else if (strcmp(argv[i], "--sequential") == 0 && i + 1 < argc) {
			sequential = argv[++i] == "true" ? true : false;
		} else if (strcmp(argv[i], "--random") == 0 && i + 1 < argc) {
			random_keys = argv[++i] == "true" ? true : false;
		} else if (strcmp(argv[i], "--key-count") == 0 && i + 1 < argc) {
			key_count = std::stoull(argv[++i]);
		} else if (strcmp(argv[i], "--key") == 0 && i + 8 < argc) {
			for (int j = 0; j < 8; ++j) {
				keyBytes[j] =static_cast<BYTE>(std::stoi(argv[++i], nullptr, 16));
			}
		} else {
			std::cerr << "Unknown or incomplete argument: " << argv[i] << std::endl;
		}
	}
	if (parallel) {
		std::chrono::high_resolution_clock::time_point start_time = std::chrono::high_resolution_clock::now();
		MPI_Init(&argc, &argv);

		int rank, size;
		MPI_Comm_rank(MPI_COMM_WORLD, &rank);
		MPI_Comm_size(MPI_COMM_WORLD, &size);

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

		std::cout << "Key [ ";
		for (BYTE b : keyBytes) {
			printf("%02X ", b);
		}
		std::cout << "]" << std::endl;
		std::cout << "Encrypted data [ ";
		for (BYTE b : ciphertext) {
			printf("%02X ", b);
		}
		std::cout << "]" << std::endl;

		// Step 4: Decrypt the ciphertext
		std::string decryptedText;
		if (!DecryptDES(ciphertext, decryptedText, hKey)) {
			std::cerr << "Decryption failed" << std::endl;
			BCryptDestroyKey(hKey);
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			return 1;
		}

		std::cout << "Decrypted text -> " << decryptedText << std::endl;
		std::cout << "--------------------------------------------------------" << std::endl;

		// Step 5: Brute force
		uint64_t totalKeys = 1024;
		uint64_t keysPerProcess = totalKeys / size;
		uint64_t start = rank * keysPerProcess;
		uint64_t end = (rank == size - 1) ? totalKeys : start + keysPerProcess;

		std::string bruteDecryptedText;
		BYTE bruteKeyBytes[8] = { 0 };
		std::vector<BCRYPT_KEY_HANDLE> hKeys;
		if (random_keys) {
			hKeys = generateRandomKeys(hAlgorithm, start, end);
		}
		else {
			hKeys = generateOrderedKeys(hAlgorithm, start, end);
		}

		bool found = false;

		// Each process tries its range of keys
		for (BCRYPT_KEY_HANDLE key : hKeys) {
			if (tryKey(ciphertext, bruteDecryptedText, key)) {
				if (bruteDecryptedText == plaintext) {
					found = true;
					std::cout << "Process [" << rank << "] [ ";
					for (BYTE b : keyBytes) {
						printf("%02X ", b);
					}
					std::cout << "] -> " << bruteDecryptedText << std::endl;
					break;
				}
			}
		}
		if (not found) {
			std::cout << "Key Not Found" << std::endl;
		}

		// Clean up and finalize MPI
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		MPI_Finalize();

		std::chrono::high_resolution_clock::time_point end_time = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> delta_seconds = end_time - start_time;
		std::cout << std::endl << "Delta time: " << delta_seconds.count() << " seconds" << std::endl;
		std::cout << "--------------------------------------------------------" << std::endl;
		return 0;
	}
	else if (sequential) {
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

		std::cout << "Key [ ";
		for (BYTE b : keyBytes) {
			printf("%02X ", b);
		}
		std::cout << "]" << std::endl;
		std::cout << "Encrypted data [ ";
		for (BYTE b : ciphertext) {
			printf("%02X ", b);
		}
		std::cout << "]" << std::endl;

		// Step 4: Decrypt the ciphertext
		std::string decryptedText;
		if (!DecryptDES(ciphertext, decryptedText, hKey)) {
			std::cerr << "Decryption failed" << std::endl;
			BCryptDestroyKey(hKey);
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			return 1;
		}

		std::cout << "Decrypted text -> " << decryptedText << std::endl;
		std::cout << "--------------------------------------------------------" << std::endl;

		// Step 5: Brute force
		std::string bruteDecryptedText;
		std::vector<BCRYPT_KEY_HANDLE> hKeys;
		if (random_keys) {
			hKeys = generateRandomKeys(hAlgorithm, 0, key_count);
		}
		else {
			hKeys = generateOrderedKeys(hAlgorithm, 0, key_count);
		}

		std::chrono::high_resolution_clock::time_point start_time = std::chrono::high_resolution_clock::now();
		for (BCRYPT_KEY_HANDLE key : hKeys) {
			if (tryKey(ciphertext, bruteDecryptedText, key)) {
				if (bruteDecryptedText == plaintext) {
					std::cout << "BruteForce  [ ";
					for (BYTE b : keyBytes) {
						printf("%02X ", b);
					}
					std::cout << "] -> " << bruteDecryptedText << std::endl;
					break;
				}
			}
		}

		std::chrono::high_resolution_clock::time_point end_time = std::chrono::high_resolution_clock::now();
		std::chrono::duration<double> delta_seconds = end_time - start_time;
		std::cout << std::endl << "Delta time: " << delta_seconds.count() << " seconds" << std::endl;
		std::cout << "--------------------------------------------------------" << std::endl;
		// Clean up
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		return 0;
	}
	else {
		int rank, num_processes;
		MPI_Init(&argc, &argv);

		MPI_Comm_rank(MPI_COMM_WORLD, &rank);
		MPI_Comm_size(MPI_COMM_WORLD, &num_processes);

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
		// Step 4: Decrypt the ciphertext
		std::string decryptedText;
		if (!DecryptDES(ciphertext, decryptedText, hKey)) {
			std::cerr << "Decryption failed" << std::endl;
			BCryptDestroyKey(hKey);
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			return 1;
		}

		std::chrono::high_resolution_clock::time_point start_time;
		std::chrono::high_resolution_clock::time_point end_time;
		std::chrono::duration<double> sequential_seconds;

		if (rank == 0) {
			std::cout << "Key [ ";
			for (BYTE b : keyBytes) {
				printf("%02X ", b);
			}
			std::cout << "]" << std::endl;
			std::cout << "Encrypted data [ ";
			for (BYTE b : ciphertext) {
				printf("%02X ", b);
			}
			std::cout << "]" << std::endl;

			std::cout << "Decrypted text -> " << decryptedText << std::endl;
			std::cout << "--------------------------------------------------------" << std::endl;

			// Step 5: Brute force
			bool found = false;
			std::string bruteDecryptedText;
			std::vector<BCRYPT_KEY_HANDLE> hKeys;
			if (random_keys) {
				hKeys = generateRandomKeys(hAlgorithm, 0, key_count);
			}
			else {
				hKeys = generateOrderedKeys(hAlgorithm, 0, key_count);
			}

			start_time = std::chrono::high_resolution_clock::now();
			for (BCRYPT_KEY_HANDLE key : hKeys) {
				if (tryKey(ciphertext, bruteDecryptedText, key)) {
					if (bruteDecryptedText == plaintext) {
						found = true;
						std::cout << "BruteForce  [ ";
						for (BYTE b : keyBytes) {
							printf("%02X ", b);
						}
						std::cout << "] -> " << bruteDecryptedText << std::endl;
						break;
					}
				}
			}
			if (not found) {
				std::cout << "Key Not Found" << std::endl;
			}

			end_time = std::chrono::high_resolution_clock::now();
			sequential_seconds = end_time - start_time;

			std::cout << std::endl << "Sequential Delta time: " << sequential_seconds.count() << " seconds" << std::endl;
			std::cout << "--------------------------------------------------------" << std::endl;
		}
		MPI_Barrier(MPI_COMM_WORLD);
		{
			// Step 5: Brute force
			uint64_t keysPerProcess = key_count / num_processes;
			uint64_t start = rank * keysPerProcess;
			uint64_t end = (rank == num_processes - 1) ? key_count : start + keysPerProcess;

			std::string bruteDecryptedText;
			std::vector<BCRYPT_KEY_HANDLE> hKeys;
			if (random_keys) {
				hKeys = generateRandomKeys(hAlgorithm, start, end);
			}
			else {
				hKeys = generateOrderedKeys(hAlgorithm, start, end);
			}

			bool found = false;
			// Each process tries its range of keys
			start_time = std::chrono::high_resolution_clock::now();

			for (BCRYPT_KEY_HANDLE key : hKeys) {
				if (tryKey(ciphertext, bruteDecryptedText, key)) {
					if (bruteDecryptedText == plaintext) {
						found = true;

						std::cout << "Process [" << rank << "] [ ";
						for (BYTE b : keyBytes) {
							printf("%02X ", b);
						}
						std::cout << "] -> " << bruteDecryptedText << std::endl;
						break;
					}
				}
			}
			int foundFlag = found ? 1 : 0;
			int globalFoundFlag = 0;
			MPI_Allreduce(&foundFlag, &globalFoundFlag, 1, MPI_INT, MPI_SUM, MPI_COMM_WORLD);

			if (globalFoundFlag ==  0 and rank == 0) {
				std::cout << "Key Not Found" << std::endl;
			}

			// Clean up and finalize MPI
			BCryptCloseAlgorithmProvider(hAlgorithm, 0);
			MPI_Finalize();
		}

		end_time = std::chrono::high_resolution_clock::now();

		if (rank == 0) {
			std::chrono::duration<double> openmpi_seconds = end_time - start_time;
			std::cout << std::endl << "Open MPI Delta time: " << openmpi_seconds.count() << " seconds" << std::endl;
			std::cout << "--------------------------------------------------------" << std::endl;
			std::cout << "Performance Metrics" << std::endl;
			std::cout << "    Efficiency: " << sequential_seconds / (double(num_processes) * openmpi_seconds) << std::endl;
			std::cout << "--------------------------------------------------------" << std::endl;
		}
		return 0;
	}
}