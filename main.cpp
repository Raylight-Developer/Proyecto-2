#include "Crypt.hpp"

/**
 * @brief Main function to perform encryption, decryption, and brute force attack using DES algorithm.
 * 
 * The program can be run in parallel using MPI or sequentially. It supports key generation in different
 * modes and the option to provide text directly or through a file. The program also measures performance
 * metrics when executed in parallel.
 * 
 * @param argc Number of command line arguments.
 * @param argv Array of command line arguments.
 * @return int Returns 0 on success, 1 on failure.
 */
int main(int argc, char** argv) {
	bool parallel = false;
	bool sequential = false;
	std::string text = "";
	std::string text_file = "./input.txt";
	uint8_t key_gen_mode = 0;
	uint64_t key_step = 1;
	uint64_t key_count = 1024 * 1024;
	BYTE keyBytes[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	for (int i = 1; i < argc; ++i) {
		if (strcmp(argv[i], "--parallel") == 0 && i + 1 < argc) {
			parallel = std::stoi(argv[++i]);
		} else if (strcmp(argv[i], "--sequential") == 0 && i + 1 < argc) {
			sequential = std::stoi(argv[++i]);
		 }else if (strcmp(argv[i], "--key-gen-mode") == 0 && i + 1 < argc) {
			key_gen_mode = std::stoul(argv[++i]);
		} else if (strcmp(argv[i], "--key-count") == 0 && i + 1 < argc) {
			key_count = std::stoull(argv[++i]);
		} else if (strcmp(argv[i], "--key-step") == 0 && i + 1 < argc) {
			key_step = std::stoull(argv[++i]);
		} else if (strcmp(argv[i], "--text") == 0 && i + 1 < argc) {
			text = argv[++i];
		} else if (strcmp(argv[i], "--text-file") == 0 && i + 1 < argc) {
			text_file = argv[++i];
		} else if (strcmp(argv[i], "--key") == 0 && i + 8 < argc) {
			for (int j = 0; j < 8; ++j) {
				keyBytes[j] =static_cast<BYTE>(std::stoi(argv[++i], nullptr, 16));
			}
		} else {
			std::cerr << "Unknown or incomplete argument: " << argv[i] << std::endl;
		}
	}

	if (text == "") {
		std::ifstream file(text_file);
		if (!file.is_open()) {
			std::cerr << "Error opening file!" << std::endl;
			return 1;
		}

		std::stringstream buffer;
		buffer << file.rdbuf();
		text = buffer.str();
		file.close();
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
		std::vector<BYTE> ciphertext;
		if (!EncryptDES(text, ciphertext, hKey)) {
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
		switch (key_gen_mode) {
			case 0:
				hKeys = generateAscendingKeys(hAlgorithm, start, end);
				break;
			case 1:
				hKeys = generateDescendingKeys(hAlgorithm, start, end);
				break;
			case 2:
				hKeys = generateSteppedKeys(hAlgorithm, start, end, key_step);
				break;
			case 3:
				hKeys = generateRandomKeys(hAlgorithm, start, end);
				break;
		}

		bool found = false;

		// Each process tries its range of keys
		for (BCRYPT_KEY_HANDLE key : hKeys) {
			if (tryKey(ciphertext, bruteDecryptedText, key)) {
				if (bruteDecryptedText == text) {
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
		std::vector<BYTE> ciphertext;
		if (!EncryptDES(text, ciphertext, hKey)) {
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
		switch (key_gen_mode) {
			case 0:
				hKeys = generateAscendingKeys(hAlgorithm, 0, key_count);
				break;
			case 1:
				hKeys = generateDescendingKeys(hAlgorithm, 0, key_count);
				break;
			case 2:
				hKeys = generateSteppedKeys(hAlgorithm, 0, key_count, key_step);
				break;
			case 3:
				hKeys = generateRandomKeys(hAlgorithm, 0, key_count);
				break;
		}

		std::chrono::high_resolution_clock::time_point start_time = std::chrono::high_resolution_clock::now();
		for (BCRYPT_KEY_HANDLE key : hKeys) {
			if (tryKey(ciphertext, bruteDecryptedText, key)) {
				if (bruteDecryptedText == text) {
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
		std::vector<BYTE> ciphertext;
		if (!EncryptDES(text, ciphertext, hKey)) {
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
		double sequential_seconds;

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
			switch (key_gen_mode) {
				case 0:
					hKeys = generateAscendingKeys(hAlgorithm, 0, key_count);
					break;
				case 1:
					hKeys = generateDescendingKeys(hAlgorithm, 0, key_count);
					break;
				case 2:
					hKeys = generateSteppedKeys(hAlgorithm, 0, key_count, key_step);
					break;
				case 3:
					hKeys = generateRandomKeys(hAlgorithm, 0, key_count);
					break;
			}


			start_time = std::chrono::high_resolution_clock::now();
			for (BCRYPT_KEY_HANDLE key : hKeys) {
				if (tryKey(ciphertext, bruteDecryptedText, key)) {
					if (bruteDecryptedText == text) {
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
			sequential_seconds = std::chrono::duration<double>(end_time - start_time).count();

			std::cout << std::endl << "Sequential Delta time: " << sequential_seconds << " seconds" << std::endl;
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
			switch (key_gen_mode) {
				case 0:
					hKeys = generateAscendingKeys(hAlgorithm, start, end);
					break;
				case 1:
					hKeys = generateDescendingKeys(hAlgorithm, start, end);
					break;
				case 2:
					hKeys = generateSteppedKeys(hAlgorithm, start, end, key_step);
					break;
				case 3:
					hKeys = generateRandomKeys(hAlgorithm, start, end);
					break;
			}

			bool found = false;
			// Each process tries its range of keys
			start_time = std::chrono::high_resolution_clock::now();

			for (BCRYPT_KEY_HANDLE key : hKeys) {
				if (tryKey(ciphertext, bruteDecryptedText, key)) {
					if (bruteDecryptedText == text) {
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

	
		return 0;
	}
}