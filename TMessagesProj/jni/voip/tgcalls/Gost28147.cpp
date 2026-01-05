/*
 * GOST 28147-89 Block Cipher Implementation
 */

#include "Gost28147.h"
#include <cstring>

namespace tgcalls {

// Define static S-boxes
constexpr uint8_t Gost28147::SBOX[8][16];

Gost28147::Gost28147(const uint8_t* key) {
    // Split 256-bit key into 8 32-bit subkeys (little-endian)
    for (int i = 0; i < 8; i++) {
        _subkeys[i] = static_cast<uint32_t>(key[i * 4]) |
                      (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
                      (static_cast<uint32_t>(key[i * 4 + 2]) << 16) |
                      (static_cast<uint32_t>(key[i * 4 + 3]) << 24);
    }
}

Gost28147::Gost28147(const std::vector<uint8_t>& key) {
    if (key.size() >= KEY_SIZE) {
        for (int i = 0; i < 8; i++) {
            _subkeys[i] = static_cast<uint32_t>(key[i * 4]) |
                          (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
                          (static_cast<uint32_t>(key[i * 4 + 2]) << 16) |
                          (static_cast<uint32_t>(key[i * 4 + 3]) << 24);
        }
    } else {
        // Pad with zeros if key is too short
        std::vector<uint8_t> paddedKey(KEY_SIZE, 0);
        std::memcpy(paddedKey.data(), key.data(), key.size());
        for (int i = 0; i < 8; i++) {
            _subkeys[i] = static_cast<uint32_t>(paddedKey[i * 4]) |
                          (static_cast<uint32_t>(paddedKey[i * 4 + 1]) << 8) |
                          (static_cast<uint32_t>(paddedKey[i * 4 + 2]) << 16) |
                          (static_cast<uint32_t>(paddedKey[i * 4 + 3]) << 24);
        }
    }
}

uint32_t Gost28147::roundFunction(uint32_t data, uint32_t subkey) const {
    // Add subkey modulo 2^32
    uint32_t sum = data + subkey;
    
    // S-box substitution (4 bits at a time through 8 S-boxes)
    uint32_t result = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t nibble = (sum >> (i * 4)) & 0x0F;
        result |= static_cast<uint32_t>(SBOX[i][nibble]) << (i * 4);
    }
    
    // Rotate left by 11 bits
    return (result << 11) | (result >> 21);
}

void Gost28147::feistelRound(uint32_t& left, uint32_t& right, uint32_t subkey) const {
    uint32_t temp = right;
    right = left ^ roundFunction(right, subkey);
    left = temp;
}

void Gost28147::encryptBlock(const uint8_t* input, uint8_t* output) const {
    // Read block as two 32-bit words (little-endian)
    uint32_t left = static_cast<uint32_t>(input[0]) |
                    (static_cast<uint32_t>(input[1]) << 8) |
                    (static_cast<uint32_t>(input[2]) << 16) |
                    (static_cast<uint32_t>(input[3]) << 24);
    
    uint32_t right = static_cast<uint32_t>(input[4]) |
                     (static_cast<uint32_t>(input[5]) << 8) |
                     (static_cast<uint32_t>(input[6]) << 16) |
                     (static_cast<uint32_t>(input[7]) << 24);
    
    // 32 rounds: 24 rounds with keys 0-7 (3 times), then 8 rounds with keys 7-0
    // Rounds 1-24: keys in order 0,1,2,3,4,5,6,7 repeated 3 times
    for (int round = 0; round < 24; round++) {
        feistelRound(left, right, _subkeys[round % 8]);
    }
    
    // Rounds 25-32: keys in reverse order 7,6,5,4,3,2,1,0
    for (int round = 0; round < 8; round++) {
        feistelRound(left, right, _subkeys[7 - round]);
    }
    
    // Final swap (undo the last Feistel swap)
    uint32_t temp = left;
    left = right;
    right = temp;
    
    // Write output (little-endian)
    output[0] = left & 0xFF;
    output[1] = (left >> 8) & 0xFF;
    output[2] = (left >> 16) & 0xFF;
    output[3] = (left >> 24) & 0xFF;
    output[4] = right & 0xFF;
    output[5] = (right >> 8) & 0xFF;
    output[6] = (right >> 16) & 0xFF;
    output[7] = (right >> 24) & 0xFF;
}

void Gost28147::decryptBlock(const uint8_t* input, uint8_t* output) const {
    // Read block as two 32-bit words (little-endian)
    uint32_t left = static_cast<uint32_t>(input[0]) |
                    (static_cast<uint32_t>(input[1]) << 8) |
                    (static_cast<uint32_t>(input[2]) << 16) |
                    (static_cast<uint32_t>(input[3]) << 24);
    
    uint32_t right = static_cast<uint32_t>(input[4]) |
                     (static_cast<uint32_t>(input[5]) << 8) |
                     (static_cast<uint32_t>(input[6]) << 16) |
                     (static_cast<uint32_t>(input[7]) << 24);
    
    // Decryption uses reverse key schedule
    // Rounds 1-8: keys in order 0,1,2,3,4,5,6,7
    for (int round = 0; round < 8; round++) {
        feistelRound(left, right, _subkeys[round]);
    }
    
    // Rounds 9-32: keys in reverse order 7,6,5,4,3,2,1,0 repeated 3 times
    for (int round = 0; round < 24; round++) {
        feistelRound(left, right, _subkeys[7 - (round % 8)]);
    }
    
    // Final swap
    uint32_t temp = left;
    left = right;
    right = temp;
    
    // Write output (little-endian)
    output[0] = left & 0xFF;
    output[1] = (left >> 8) & 0xFF;
    output[2] = (left >> 16) & 0xFF;
    output[3] = (left >> 24) & 0xFF;
    output[4] = right & 0xFF;
    output[5] = (right >> 8) & 0xFF;
    output[6] = (right >> 16) & 0xFF;
    output[7] = (right >> 24) & 0xFF;
}

void Gost28147::ctr(const uint8_t* nonce, uint64_t counter,
                    const uint8_t* input, uint8_t* output, size_t length) const {
    uint8_t counterBlock[BLOCK_SIZE];
    uint8_t keystream[BLOCK_SIZE];
    
    size_t offset = 0;
    while (offset < length) {
        // Build counter block: nonce (first 4 bytes) + counter (last 4 bytes)
        // Using only 32-bit counter for simplicity (4GB max per nonce)
        std::memcpy(counterBlock, nonce, 4);
        uint32_t ctr32 = static_cast<uint32_t>(counter);
        counterBlock[4] = ctr32 & 0xFF;
        counterBlock[5] = (ctr32 >> 8) & 0xFF;
        counterBlock[6] = (ctr32 >> 16) & 0xFF;
        counterBlock[7] = (ctr32 >> 24) & 0xFF;
        
        // Encrypt counter block to get keystream
        encryptBlock(counterBlock, keystream);
        
        // XOR with input
        size_t blockLen = (length - offset < BLOCK_SIZE) ? (length - offset) : BLOCK_SIZE;
        for (size_t i = 0; i < blockLen; i++) {
            output[offset + i] = input[offset + i] ^ keystream[i];
        }
        
        offset += blockLen;
        counter++;
    }
}

void Gost28147::ctrEncrypt(const uint8_t* key, const uint8_t* nonce, uint64_t counter,
                           const uint8_t* input, uint8_t* output, size_t length) {
    Gost28147 cipher(key);
    cipher.ctr(nonce, counter, input, output, length);
}

} // namespace tgcalls

