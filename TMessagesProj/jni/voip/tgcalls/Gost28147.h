/*
 * GOST 28147-89 Block Cipher Implementation
 * 
 * Block size: 64 bits (8 bytes)
 * Key size: 256 bits (32 bytes)
 * Rounds: 32
 * 
 * This implementation supports:
 * - ECB mode (single block encrypt/decrypt)
 * - CTR mode (for stream encryption)
 */

#ifndef TGCALLS_GOST_28147_H
#define TGCALLS_GOST_28147_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>

namespace tgcalls {

class Gost28147 {
public:
    static constexpr size_t BLOCK_SIZE = 8;  // 64 bits
    static constexpr size_t KEY_SIZE = 32;   // 256 bits
    
    // S-boxes from RFC 4357 (id-GostR3411-94-CryptoProParamSet)
    // These are the CryptoPro S-boxes, widely used in Russia
    static constexpr uint8_t SBOX[8][16] = {
        {10, 4, 5, 6, 8, 1, 3, 7, 13, 12, 14, 0, 9, 2, 11, 15},
        {5, 15, 4, 0, 2, 13, 11, 9, 1, 7, 6, 3, 12, 14, 10, 8},
        {7, 15, 12, 14, 9, 4, 1, 0, 3, 11, 5, 2, 6, 10, 8, 13},
        {4, 10, 7, 12, 0, 15, 2, 8, 14, 1, 6, 5, 13, 11, 9, 3},
        {7, 6, 4, 11, 9, 12, 2, 10, 1, 8, 0, 14, 15, 13, 3, 5},
        {7, 6, 2, 4, 13, 9, 15, 0, 10, 1, 5, 11, 8, 14, 12, 3},
        {13, 14, 4, 1, 7, 0, 5, 10, 3, 12, 8, 15, 6, 2, 9, 11},
        {1, 3, 10, 9, 5, 11, 4, 15, 8, 6, 7, 14, 13, 0, 2, 12}
    };
    
    /**
     * Initialize with 256-bit key
     */
    explicit Gost28147(const uint8_t* key);
    explicit Gost28147(const std::vector<uint8_t>& key);
    
    /**
     * Encrypt a single 64-bit block
     * @param input 8-byte input block
     * @param output 8-byte output block (can be same as input)
     */
    void encryptBlock(const uint8_t* input, uint8_t* output) const;
    
    /**
     * Decrypt a single 64-bit block
     * @param input 8-byte input block
     * @param output 8-byte output block (can be same as input)
     */
    void decryptBlock(const uint8_t* input, uint8_t* output) const;
    
    /**
     * CTR mode encryption/decryption (same operation)
     * @param nonce 8-byte nonce/IV
     * @param counter Starting counter value
     * @param input Input data
     * @param output Output data (can be same as input)
     * @param length Data length in bytes
     */
    void ctr(const uint8_t* nonce, uint64_t counter,
             const uint8_t* input, uint8_t* output, size_t length) const;
    
    /**
     * Static CTR encryption with key
     */
    static void ctrEncrypt(const uint8_t* key, const uint8_t* nonce, uint64_t counter,
                           const uint8_t* input, uint8_t* output, size_t length);
    
private:
    // 8 32-bit subkeys derived from 256-bit key
    std::array<uint32_t, 8> _subkeys;
    
    /**
     * GOST round function (f-function)
     */
    uint32_t roundFunction(uint32_t data, uint32_t subkey) const;
    
    /**
     * Core Feistel round
     */
    void feistelRound(uint32_t& left, uint32_t& right, uint32_t subkey) const;
};

} // namespace tgcalls

#endif // TGCALLS_GOST_28147_H

