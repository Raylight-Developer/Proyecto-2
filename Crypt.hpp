#pragma once

#include <iostream>
#include <iomanip>
#include <random>
#include <vector>
#include <chrono>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include <windows.h>
#include <bcrypt.h>
#include <mpi.h>

#undef min
#undef max

#pragma comment(lib, "bcrypt.lib")
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

bool EncryptDES(const std::string& plaintext, std::vector<BYTE>& ciphertext, BCRYPT_KEY_HANDLE hKey);
bool DecryptDES(const std::vector<BYTE>& ciphertext, std::string& plaintext, BCRYPT_KEY_HANDLE hKey);
bool tryKey(const std::vector<BYTE>& ciphertext, std::string& decryptedText, BCRYPT_KEY_HANDLE hKey);

std::vector<BCRYPT_KEY_HANDLE> generateRandomKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end);
std::vector<BCRYPT_KEY_HANDLE> generateAscendingKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end);
std::vector<BCRYPT_KEY_HANDLE> generateDescendingKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end);
std::vector<BCRYPT_KEY_HANDLE> generateSteppedKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end, const uint64_t steps);