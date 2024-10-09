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

/**
 * @brief Encrypts a plaintext message using DES encryption.
 * 
 * @param plaintext The string containing the plaintext message to be encrypted.
 * @param ciphertext A vector of BYTEs that will hold the resulting encrypted message.
 * @param hKey The DES key handle used for encryption.
 * @return true if encryption was successful, false otherwise.
 */
bool EncryptDES(const std::string& plaintext, std::vector<BYTE>& ciphertext, BCRYPT_KEY_HANDLE hKey);

/**
 * @brief Decrypts a ciphertext message encrypted with DES.
 * 
 * @param ciphertext A vector of BYTEs containing the encrypted message.
 * @param plaintext The string that will hold the resulting decrypted message.
 * @param hKey The DES key handle used for decryption.
 * @return true if decryption was successful, false otherwise.
 */
bool DecryptDES(const std::vector<BYTE>& ciphertext, std::string& plaintext, BCRYPT_KEY_HANDLE hKey);

/**
 * @brief Attempts to decrypt the ciphertext using the provided key and checks if the result matches an expected value.
 * 
 * @param ciphertext A vector of BYTEs containing the encrypted message.
 * @param decryptedText The string that will hold the resulting decrypted message if the key is correct.
 * @param hKey The DES key handle to try for decryption.
 * @return true if the decryption is successful and matches the expected value, false otherwise.
 */
bool tryKey(const std::vector<BYTE>& ciphertext, std::string& decryptedText, BCRYPT_KEY_HANDLE hKey);

/**
 * @brief Generates a list of random DES keys within the specified range.
 * 
 * @param hAlgorithm The algorithm handle used for generating the keys.
 * @param start The starting value of the key range.
 * @param end The ending value of the key range.
 * @return A vector containing randomly generated DES key handles.
 */
std::vector<BCRYPT_KEY_HANDLE> generateRandomKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end);

/**
 * @brief Generates a list of ascending DES keys within the specified range.
 * 
 * @param hAlgorithm The algorithm handle used for generating the keys.
 * @param start The starting value of the key range.
 * @param end The ending value of the key range.
 * @return A vector containing ascending DES key handles.
 */
std::vector<BCRYPT_KEY_HANDLE> generateAscendingKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end);

/**
 * @brief Generates a list of descending DES keys within the specified range.
 * 
 * @param hAlgorithm The algorithm handle used for generating the keys.
 * @param start The starting value of the key range.
 * @param end The ending value of the key range.
 * @return A vector containing descending DES key handles.
 */
std::vector<BCRYPT_KEY_HANDLE> generateDescendingKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end);

/**
 * @brief Generates a list of DES keys within the specified range with a specified step between each key.
 * 
 * @param hAlgorithm The algorithm handle used for generating the keys.
 * @param start The starting value of the key range.
 * @param end The ending value of the key range.
 * @param steps The number of steps between each key in the range.
 * @return A vector containing DES key handles generated at specified step intervals.
 */
std::vector<BCRYPT_KEY_HANDLE> generateSteppedKeys(BCRYPT_ALG_HANDLE hAlgorithm, const uint64_t& start, const uint64_t& end, const uint64_t steps);