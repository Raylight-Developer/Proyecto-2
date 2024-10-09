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

BCRYPT_KEY_HANDLE generateAscendingKey(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& i);
BCRYPT_KEY_HANDLE generateDescendingKey(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& i);
BCRYPT_KEY_HANDLE generateRandomKey(BCRYPT_ALG_HANDLE hAlgorithm);

BCRYPT_KEY_HANDLE generateKey(BCRYPT_ALG_HANDLE hAlgorithm, uint64_t& i, uint64_t& step, const uint8_t mode);