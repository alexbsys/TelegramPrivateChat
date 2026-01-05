#include "FrameCryptors.h"
#include "Gost28147.h"
#include <openssl/rand.h>
#include <cstring>
#include <algorithm>
#include <android/log.h>

#define LOG_TAG "FrameCryptors"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace tgcalls {

// ==================== Emulation Prevention Helpers ====================

// Write data with emulation prevention bytes (escaping 00 00 00/01/02/03)
static size_t WriteWithEmulationPrevention(const uint8_t* src, size_t srcSize, 
                                            uint8_t* dst, size_t dstMaxSize) {
    size_t srcPos = 0, dstPos = 0;
    int zeroCount = 0;
    
    while (srcPos < srcSize && dstPos < dstMaxSize) {
        uint8_t byte = src[srcPos++];
        
        if (zeroCount >= 2 && byte <= 3) {
            // Need to insert emulation prevention byte
            if (dstPos >= dstMaxSize) return 0;  // No space
            dst[dstPos++] = 0x03;
            zeroCount = 0;
        }
        
        if (dstPos >= dstMaxSize) return 0;
        dst[dstPos++] = byte;
        
        if (byte == 0) zeroCount++;
        else zeroCount = 0;
    }
    
    return (srcPos == srcSize) ? dstPos : 0;
}

// Read data removing emulation prevention bytes
static size_t ReadWithEmulationPreventionRemoval(const uint8_t* src, size_t srcSize,
                                                   uint8_t* dst, size_t dstMaxSize) {
    size_t srcPos = 0, dstPos = 0;
    int zeroCount = 0;
    
    while (srcPos < srcSize && dstPos < dstMaxSize) {
        uint8_t byte = src[srcPos++];
        
        if (zeroCount >= 2 && byte == 0x03 && srcPos < srcSize) {
            // This is an emulation prevention byte, skip it
            uint8_t nextByte = src[srcPos];
            if (nextByte <= 3) {
                zeroCount = 0;
                continue;  // Skip the 0x03
            }
        }
        
        dst[dstPos++] = byte;
        
        if (byte == 0) zeroCount++;
        else zeroCount = 0;
    }
    
    return dstPos;
}

// Calculate size after adding emulation prevention bytes
static size_t CalculateEscapedSize(const uint8_t* data, size_t size) {
    size_t escaped = size;
    int zeroCount = 0;
    for (size_t i = 0; i < size; i++) {
        if (zeroCount >= 2 && data[i] <= 3) {
            escaped++;  // Will need an extra 0x03
            zeroCount = 0;
        }
        if (data[i] == 0) zeroCount++;
        else zeroCount = 0;
    }
    return escaped;
}

// ==================== NAL Unit Parsing Helpers ====================

struct NalUnitInfo {
    size_t start_offset;     // Offset of start code
    size_t header_size;      // Start code + NAL header bytes
    size_t payload_size;     // Payload size (excluding header, until next NAL or end)
    bool should_encrypt;
};

static bool ShouldEncryptNalType(uint8_t nal_type, bool isH265) {
    if (isH265) {
        // H.265: VCL NAL types are 0-31
        return (nal_type <= 31);
    } else {
        // H.264: VCL NAL types are 1-5 (slices)
        return (nal_type >= 1 && nal_type <= 5);
    }
}

// Find NAL units in PLAINTEXT video frame
// This should only be called on unencrypted data during encryption
static std::vector<NalUnitInfo> FindNalUnits(const uint8_t* data, size_t size, bool isH265) {
    std::vector<NalUnitInfo> nalUnits;
    size_t i = 0;
    
    while (i + 4 < size) {
        size_t start_code_len = 0;
        if (data[i] == 0 && data[i+1] == 0) {
            if (data[i+2] == 1) {
                start_code_len = 3;
            } else if (data[i+2] == 0 && i + 3 < size && data[i+3] == 1) {
                start_code_len = 4;
            }
        }
        
        if (start_code_len > 0) {
            NalUnitInfo info;
            info.start_offset = i;
            
            size_t header_offset = i + start_code_len;
            if (header_offset >= size) break;
            
            uint8_t first_byte = data[header_offset];
            uint8_t nal_type;
            
            if (isH265) {
                nal_type = (first_byte >> 1) & 0x3F;
                info.header_size = start_code_len + 2;
            } else {
                nal_type = first_byte & 0x1F;
                info.header_size = start_code_len + 1;
            }
            
            info.should_encrypt = ShouldEncryptNalType(nal_type, isH265);
            info.payload_size = 0;  // Will be calculated later
            nalUnits.push_back(info);
            i += info.header_size;
        } else {
            i++;
        }
    }
    
    // Calculate payload sizes
    for (size_t j = 0; j < nalUnits.size(); j++) {
        size_t payloadStart = nalUnits[j].start_offset + nalUnits[j].header_size;
        size_t nextNal = (j + 1 < nalUnits.size()) ? nalUnits[j + 1].start_offset : size;
        nalUnits[j].payload_size = (nextNal > payloadStart) ? (nextNal - payloadStart) : 0;
    }
    
    return nalUnits;
}

static bool DetectH265(const uint8_t* data, size_t size) {
    // Only check the FIRST NAL unit to avoid false positives from encrypted data
    // that might contain byte sequences looking like start codes
    
    if (size < 6) return false;  // Need at least 2 bytes of NAL header for H.265
    
    // Find first start code (00 00 01 or 00 00 00 01)
    size_t start_code_len = 0;
    size_t header_offset = 0;
    
    // Check for 4-byte start code first (00 00 00 01)
    if (size >= 5 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) {
        start_code_len = 4;
        header_offset = 4;
    }
    // Check for 3-byte start code (00 00 01)
    else if (size >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 1) {
        start_code_len = 3;
        header_offset = 3;
    }
    
    if (start_code_len == 0) return false;
    if (header_offset + 1 >= size) return false;  // Need 2 bytes for H.265 header
    
    uint8_t first_byte = data[header_offset];
    uint8_t second_byte = data[header_offset + 1];
    uint8_t forbidden_bit = (first_byte >> 7) & 0x01;
    
    if (forbidden_bit != 0) return false;
    
    // Check NAL type for codec detection
    uint8_t nal_type_h264 = first_byte & 0x1F;
    uint8_t nal_type_h265 = (first_byte >> 1) & 0x3F;
    
    // H.265 VPS/SPS/PPS types are 32-40
    if (nal_type_h265 >= 32 && nal_type_h265 <= 40) {
        return true;  // Definitely H.265
    }
    
    // H.264-only NAL types (not valid in H.265)
    // SEI=6, SPS=7, PPS=8, AUD=9, End of Seq=10, End of Stream=11, Filler=12
    if (nal_type_h264 >= 6 && nal_type_h264 <= 12) {
        return false;  // Definitely H.264
    }
    
    // For slice types (1-5 in H.264, 0-31 in H.265), check second byte
    // H.265 NAL header is 2 bytes: first has type, second has layer_id + temporal_id
    // H.265 requires nuh_temporal_id_plus1 >= 1 (bits 0-2 of second byte)
    // H.264 NAL header is 1 byte, second byte is slice data (variable)
    uint8_t temporal_id_plus1 = second_byte & 0x07;
    uint8_t layer_id = ((first_byte & 0x01) << 5) | ((second_byte >> 3) & 0x1F);
    
    // Valid H.265: temporal_id_plus1 in range [1,7] and layer_id usually 0
    if (temporal_id_plus1 >= 1 && temporal_id_plus1 <= 7 && layer_id <= 63) {
        // Additional check: for most H.265 streams, layer_id is 0
        // and temporal_id_plus1 is 1 for base layer
        if (layer_id == 0 && temporal_id_plus1 == 1) {
            return true;  // Very likely H.265
        }
        // If layer_id is non-zero but valid, could still be H.265 (scalable/multi-layer)
        if (nal_type_h265 <= 31) {  // VCL NAL types
            return true;  // Likely H.265 VCL NAL
        }
    }
    
    // If temporal_id_plus1 is 0, it's invalid for H.265, so assume H.264
    if (temporal_id_plus1 == 0) {
        return false;  // Definitely H.264
    }
    
    return false;  // Default to H.264
}

// Per-NAL offset size (3 bytes for offset to trailer)
static constexpr size_t kOffsetSize = 3;

// Structure to store NAL info in trailer
// Format: [NAL_COUNT 1B][IS_H265 1B]([NAL_OFFSET 4B][NAL_HEADER_SIZE 1B][NAL_PAYLOAD_SIZE 3B][SHOULD_ENCRYPT 1B])*
static constexpr size_t kNalInfoHeaderSize = 2;  // count + isH265
static constexpr size_t kNalInfoEntrySize = 9;   // offset(4) + header(1) + payload(3) + encrypt(1)
static constexpr size_t kMaxNalUnits = 64;       // Limit to prevent huge trailers

struct NalInfoHeader {
    uint8_t nalCount;
    uint8_t isH265;
};

static size_t GetNalInfoSize(size_t nalCount) {
    return kNalInfoHeaderSize + std::min(nalCount, kMaxNalUnits) * kNalInfoEntrySize;
}

static void WriteNalInfo(uint8_t* dest, const std::vector<NalUnitInfo>& nalUnits, bool isH265) {
    size_t count = std::min(nalUnits.size(), kMaxNalUnits);
    dest[0] = static_cast<uint8_t>(count);
    dest[1] = isH265 ? 1 : 0;
    
    uint8_t* p = dest + kNalInfoHeaderSize;
    for (size_t i = 0; i < count; i++) {
        const auto& nal = nalUnits[i];
        // Offset (4 bytes, little endian)
        p[0] = (nal.start_offset) & 0xFF;
        p[1] = (nal.start_offset >> 8) & 0xFF;
        p[2] = (nal.start_offset >> 16) & 0xFF;
        p[3] = (nal.start_offset >> 24) & 0xFF;
        // Header size (1 byte)
        p[4] = static_cast<uint8_t>(nal.header_size);
        // Payload size (3 bytes, little endian)
        p[5] = (nal.payload_size) & 0xFF;
        p[6] = (nal.payload_size >> 8) & 0xFF;
        p[7] = (nal.payload_size >> 16) & 0xFF;
        // Should encrypt (1 byte)
        p[8] = nal.should_encrypt ? 1 : 0;
        p += kNalInfoEntrySize;
    }
}

static std::vector<NalUnitInfo> ReadNalInfo(const uint8_t* src, size_t maxSize, bool* isH265) {
    std::vector<NalUnitInfo> nalUnits;
    
    if (maxSize < kNalInfoHeaderSize) return nalUnits;
    
    size_t count = src[0];
    *isH265 = (src[1] != 0);
    
    if (count > kMaxNalUnits) count = kMaxNalUnits;
    if (maxSize < kNalInfoHeaderSize + count * kNalInfoEntrySize) return nalUnits;
    
    const uint8_t* p = src + kNalInfoHeaderSize;
    for (size_t i = 0; i < count; i++) {
        NalUnitInfo nal;
        nal.start_offset = static_cast<size_t>(p[0]) |
                          (static_cast<size_t>(p[1]) << 8) |
                          (static_cast<size_t>(p[2]) << 16) |
                          (static_cast<size_t>(p[3]) << 24);
        nal.header_size = p[4];
        nal.payload_size = static_cast<size_t>(p[5]) |
                          (static_cast<size_t>(p[6]) << 8) |
                          (static_cast<size_t>(p[7]) << 16);
        nal.should_encrypt = (p[8] != 0);
        nalUnits.push_back(nal);
        p += kNalInfoEntrySize;
    }
    
    return nalUnits;
}

// Helper to normalize key to 32 bytes
static std::vector<uint8_t> NormalizeKey(const std::vector<uint8_t>& key) {
    std::vector<uint8_t> result = key;
    while (result.size() < 32) result.push_back(0);
    if (result.size() > 32) result.resize(32);
    return result;
}

// ==================== AES-256-GCM Cryptor ====================

Aes256Cryptor::Aes256Cryptor() {
    _ctx = EVP_CIPHER_CTX_new();
}

Aes256Cryptor::~Aes256Cryptor() {
    if (_ctx) {
        EVP_CIPHER_CTX_free(_ctx);
    }
}

void Aes256Cryptor::SetKey(const std::vector<uint8_t>& key) {
    _key = NormalizeKey(key);
}

bool Aes256Cryptor::ComputeGmac(const uint8_t* iv, const uint8_t* aad, size_t aad_len, uint8_t* tag) {
    EVP_CIPHER_CTX_reset(_ctx);
    if (!EVP_EncryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)) return false;
    if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, kIvSize, nullptr)) return false;
    if (!EVP_EncryptInit_ex(_ctx, nullptr, nullptr, _key.data(), iv)) return false;
    
    int outLen = 0;
    if (!EVP_EncryptUpdate(_ctx, nullptr, &outLen, aad, aad_len)) return false;
    if (!EVP_EncryptFinal_ex(_ctx, nullptr, &outLen)) return false;
    if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag)) return false;
    
    return true;
}

bool Aes256Cryptor::VerifyGmac(const uint8_t* iv, const uint8_t* aad, size_t aad_len, const uint8_t* tag) {
    uint8_t computed_tag[kTagSize];
    if (!ComputeGmac(iv, aad, aad_len, computed_tag)) return false;
    return memcmp(tag, computed_tag, kTagSize) == 0;
}

bool Aes256Cryptor::EncryptCtr(const uint8_t* plaintext, uint8_t* ciphertext, size_t size, const uint8_t* iv) {
    uint8_t counter[16] = {0};
    memcpy(counter, iv, kIvSize);
    
    EVP_CIPHER_CTX* ctr_ctx = EVP_CIPHER_CTX_new();
    if (!EVP_EncryptInit_ex(ctr_ctx, EVP_aes_256_ctr(), nullptr, _key.data(), counter)) {
        EVP_CIPHER_CTX_free(ctr_ctx);
        return false;
    }
    
    int encLen;
    if (!EVP_EncryptUpdate(ctr_ctx, ciphertext, &encLen, plaintext, size)) {
        EVP_CIPHER_CTX_free(ctr_ctx);
        return false;
    }
    
    EVP_CIPHER_CTX_free(ctr_ctx);
    return true;
}

bool Aes256Cryptor::DecryptCtr(const uint8_t* ciphertext, uint8_t* plaintext, size_t size, const uint8_t* iv) {
    return EncryptCtr(ciphertext, plaintext, size, iv);  // CTR is symmetric
}

size_t Aes256Cryptor::WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum,
                                   const uint8_t* iv, const uint8_t* tag, bool isH265) {
    // SEI payload: UUID(16) + seqNum(4) + magic(1) + IV(12) + TAG(16) + trailing(1) = 50 bytes raw
    // Build raw payload with potential emulation prevention
    uint8_t rawPayload[64];
    size_t rawPos = 0;
    
    memcpy(rawPayload + rawPos, kSeiUuid, 16);
    rawPos += 16;
    
    rawPayload[rawPos++] = (seqNum >> 24) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 16) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 8) & 0xFF;
    rawPayload[rawPos++] = seqNum & 0xFF;
    
    rawPayload[rawPos++] = kVideoMagic;
    
    memcpy(rawPayload + rawPos, iv, kIvSize);
    rawPos += kIvSize;
    
    memcpy(rawPayload + rawPos, tag, kTagSize);
    rawPos += kTagSize;
    
    rawPayload[rawPos++] = 0x80;  // RBSP trailing
    
    size_t escapedPayloadSize = CalculateEscapedSize(rawPayload, rawPos);
    size_t seiPayloadSize = 16 + 4 + 1 + kIvSize + kTagSize;  // Raw size for header
    size_t headerSize = 4 + (isH265 ? 2 : 1) + 1 + (seiPayloadSize > 127 ? 2 : 1);
    size_t totalSize = headerSize + escapedPayloadSize;
    
    if (totalSize > maxSize) return 0;
    
    size_t pos = 0;
    
    // Start code
    output[pos++] = 0x00;
    output[pos++] = 0x00;
    output[pos++] = 0x00;
    output[pos++] = 0x01;
    
    // NAL header
    if (isH265) {
        output[pos++] = 0x4E;  // PREFIX_SEI_NUT
        output[pos++] = 0x01;
    } else {
        output[pos++] = 0x06;  // SEI
    }
    
    // Payload type = 5
    output[pos++] = 0x05;
    
    // Payload size
    if (seiPayloadSize > 127) {
        output[pos++] = 0xFF;
        output[pos++] = static_cast<uint8_t>(seiPayloadSize - 127);
    } else {
        output[pos++] = static_cast<uint8_t>(seiPayloadSize);
    }
    
    // Write escaped payload
    size_t written = WriteWithEmulationPrevention(rawPayload, rawPos, output + pos, maxSize - pos);
    if (written == 0) return 0;
    
    return pos + written;
}

bool Aes256Cryptor::ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info) {
    if (size < 55) return false;  // Minimum SEI size for AES
    
    size_t pos = 0;
    if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) pos = 4;
    else if (data[0] == 0 && data[1] == 0 && data[2] == 1) pos = 3;
    else return false;
    
    uint8_t nalByte = data[pos];
    if ((nalByte & 0x80) != 0) return false;
    
    uint8_t h264Type = nalByte & 0x1F;
    uint8_t h265Type = (nalByte >> 1) & 0x3F;
    if (h264Type == 6) pos += 1;
    else if (h265Type == 39 || h265Type == 40) pos += 2;
    else return false;
    
    if (pos >= size || data[pos] != 0x05) return false;
    pos++;
    
    size_t payloadSize = 0;
    while (pos < size && data[pos] == 0xFF) { payloadSize += 255; pos++; }
    if (pos >= size) return false;
    payloadSize += data[pos++];
    
    size_t expectedPayloadSize = 16 + 4 + 1 + kIvSize + kTagSize;
    if (payloadSize < expectedPayloadSize) return false;
    
    size_t remainingData = size - pos;
    if (remainingData < payloadSize) return false;
    
    // De-escape the payload
    uint8_t deescaped[80];  // Larger buffer for AES SEI
    size_t deescapedSize = ReadWithEmulationPreventionRemoval(
        data + pos, remainingData, deescaped, sizeof(deescaped));
    
    if (deescapedSize < payloadSize) return false;
    
    size_t p = 0;
    if (memcmp(deescaped + p, kSeiUuid, 16) != 0) return false;
    p += 16;
    
    info.seqNum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                  (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                  (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                  static_cast<uint32_t>(deescaped[p + 3]);
    p += 4;
    
    info.magic = deescaped[p++];
    if (info.magic != kVideoMagic) return false;
    
    info.iv.resize(kIvSize);
    memcpy(info.iv.data(), deescaped + p, kIvSize);
    p += kIvSize;
    
    info.tag.resize(kTagSize);
    memcpy(info.tag.data(), deescaped + p, kTagSize);
    
    return true;
}

CryptResult Aes256Cryptor::EncryptAudio(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    size_t requiredSize = GetMaxAudioCiphertextSize(plaintextSize);
    if (ciphertextMaxSize < requiredSize) return CryptResult::Failed();
    
    uint8_t iv[kIvSize];
    RAND_bytes(iv, kIvSize);
    
    ciphertext[0] = kAudioMagic;
    memcpy(ciphertext + 1, iv, kIvSize);
    
    EVP_CIPHER_CTX_reset(_ctx);
    if (!EVP_EncryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, _key.data(), iv)) {
        return CryptResult::Failed();
    }
    
    int outLen = 0;
    if (!EVP_EncryptUpdate(_ctx, ciphertext + 1 + kIvSize, &outLen, plaintext, plaintextSize)) {
        return CryptResult::Failed();
    }
    
    int finalLen = 0;
    if (!EVP_EncryptFinal_ex(_ctx, ciphertext + 1 + kIvSize + outLen, &finalLen)) {
        return CryptResult::Failed();
    }
    
    if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, ciphertext + 1 + kIvSize + outLen + finalLen)) {
        return CryptResult::Failed();
    }
    
    return CryptResult::Ok(1 + kIvSize + outLen + finalLen + kTagSize);
}

CryptResult Aes256Cryptor::EncryptVideo(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    // SEI-based encryption:
    // 1. Insert SEI NAL with IV+TAG before each encrypted NAL
    // 2. Encrypt NAL payload in-place using AES-CTR (same size)
    // 3. NAL structure unchanged, RTP packetizer works normally
    
    bool isH265 = DetectH265(plaintext, plaintextSize);
    auto nalUnits = FindNalUnits(plaintext, plaintextSize, isH265);
    
    if (nalUnits.empty()) {
        if (ciphertextMaxSize < plaintextSize) return CryptResult::Failed();
        memcpy(ciphertext, plaintext, plaintextSize);
        return CryptResult::Ok(plaintextSize);
    }
    
    size_t outPos = 0;
    
    for (size_t nalIdx = 0; nalIdx < nalUnits.size(); nalIdx++) {
        const auto& nal = nalUnits[nalIdx];
        size_t nalEnd = (nalIdx + 1 < nalUnits.size()) ? 
                        nalUnits[nalIdx + 1].start_offset : plaintextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        if (nal.should_encrypt && nalContentSize > 0) {
            // Generate IV
            uint8_t iv[kIvSize];
            RAND_bytes(iv, kIvSize);
            
            // Encrypt payload
            std::vector<uint8_t> encryptedPayload(nalContentSize);
            if (!EncryptCtr(plaintext + nal.start_offset + nal.header_size,
                           encryptedPayload.data(), nalContentSize, iv)) {
                return CryptResult::Failed();
            }
            
            // Compute GMAC over encrypted payload
            uint8_t tag[kTagSize];
            ComputeGmac(iv, encryptedPayload.data(), nalContentSize, tag);
            
            // Write SEI NAL with IV and TAG
            size_t seiSize = WriteSeiNal(ciphertext + outPos, ciphertextMaxSize - outPos,
                                          _seqNum++, iv, tag, isH265);
            if (seiSize == 0) return CryptResult::Failed();
            outPos += seiSize;
            
            // Write NAL header
            if (outPos + nalTotalSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            // Write encrypted payload (same size as original!)
            memcpy(ciphertext + outPos, encryptedPayload.data(), nalContentSize);
            outPos += nalContentSize;
        } else {
            // Copy NAL unchanged (SPS/PPS/VPS or non-encrypted)
            if (outPos + nalTotalSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    return CryptResult::Ok(outPos);
}

size_t Aes256Cryptor::GetMaxAudioCiphertextSize(size_t plaintextSize) const {
    return 1 + kIvSize + plaintextSize + kTagSize;
}

size_t Aes256Cryptor::GetMaxVideoCiphertextSize(size_t plaintextSize) const {
    // SEI-based: original data + SEI NAL per encrypted NAL (~60 bytes each)
    return plaintextSize + 32 * 70;
}

int Aes256Cryptor::TryFindAudioKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    if (ciphertextSize < 1 + kIvSize + kTagSize) return -1;
    
    const uint8_t* iv = ciphertext + 1;
    const uint8_t* encryptedData = ciphertext + 1 + kIvSize;
    size_t encryptedLen = ciphertextSize - 1 - kIvSize - kTagSize;
    const uint8_t* tag = ciphertext + ciphertextSize - kTagSize;
    
    std::vector<uint8_t> tempBuffer(encryptedLen);
    
    for (size_t i = 0; i < keys.size(); i++) {
        _key = NormalizeKey(keys[i]);
        
        EVP_CIPHER_CTX_reset(_ctx);
        if (!EVP_DecryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, _key.data(), iv)) continue;
        
        int outLen = 0;
        if (!EVP_DecryptUpdate(_ctx, tempBuffer.data(), &outLen, encryptedData, encryptedLen)) continue;
        if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, kTagSize, const_cast<uint8_t*>(tag))) continue;
        
        int finalLen = 0;
        if (EVP_DecryptFinal_ex(_ctx, tempBuffer.data() + outLen, &finalLen) > 0) {
            return static_cast<int>(i);
        }
    }
    
    _key.clear();
    return -1;
}

int Aes256Cryptor::TryFindVideoKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    // SEI-based: find our SEI, extract IV/TAG, verify GMAC with each key
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    PendingSeiInfo seiInfo;
    size_t encryptedNalIdx = SIZE_MAX;
    
    // Find our SEI and the following encrypted NAL
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        if (headerPos >= ciphertextSize) continue;
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = false;
        if (isH265) {
            isSei = (((nalByte >> 1) & 0x3F) == 39 || ((nalByte >> 1) & 0x3F) == 40);
        } else {
            isSei = ((nalByte & 0x1F) == 6);
        }
        
        if (isSei && ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, seiInfo)) {
            for (size_t j = i + 1; j < nalUnits.size(); j++) {
                if (nalUnits[j].should_encrypt) {
                    encryptedNalIdx = j;
                    break;
                }
            }
            break;
        }
    }
    
    if (encryptedNalIdx == SIZE_MAX) return -1;
    
    const auto& nal = nalUnits[encryptedNalIdx];
    size_t nalEnd = (encryptedNalIdx + 1 < nalUnits.size()) ? 
                    nalUnits[encryptedNalIdx + 1].start_offset : ciphertextSize;
    size_t nalContentSize = nalEnd - nal.start_offset - nal.header_size;
    
    // Try each key
    for (size_t k = 0; k < keys.size(); k++) {
        _key = NormalizeKey(keys[k]);
        
        // Verify GMAC over encrypted payload
        if (VerifyGmac(seiInfo.iv.data(), 
                       ciphertext + nal.start_offset + nal.header_size, 
                       nalContentSize, seiInfo.tag.data())) {
            return static_cast<int>(k);
        }
    }
    
    _key.clear();
    return -1;
}

CryptResult Aes256Cryptor::DecryptAudio(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    if (ciphertextSize < 1 + kIvSize + kTagSize) return CryptResult::Failed();
    
    const uint8_t* iv = ciphertext + 1;
    const uint8_t* encryptedData = ciphertext + 1 + kIvSize;
    size_t encryptedLen = ciphertextSize - 1 - kIvSize - kTagSize;
    const uint8_t* tag = ciphertext + ciphertextSize - kTagSize;
    
    if (plaintextMaxSize < encryptedLen) return CryptResult::Failed();
    
    EVP_CIPHER_CTX_reset(_ctx);
    if (!EVP_DecryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, _key.data(), iv)) {
        return CryptResult::Failed();
    }
    
    int outLen = 0;
    if (!EVP_DecryptUpdate(_ctx, plaintext, &outLen, encryptedData, encryptedLen)) {
        return CryptResult::Failed();
    }
    
    if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, kTagSize, const_cast<uint8_t*>(tag))) {
        return CryptResult::Failed();
    }
    
    int finalLen = 0;
    if (EVP_DecryptFinal_ex(_ctx, plaintext + outLen, &finalLen) <= 0) {
        return CryptResult::Failed();
    }
    
    return CryptResult::Ok(outLen + finalLen);
}

CryptResult Aes256Cryptor::DecryptVideo(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    // SEI-based decryption:
    // 1. Find SEI NALs with our UUID and extract IV/TAG
    // 2. Decrypt following VCL NAL using AES-CTR
    // 3. Skip our SEI NALs in output
    
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    if (nalUnits.empty()) {
        if (plaintextMaxSize < ciphertextSize) return CryptResult::Failed();
        memcpy(plaintext, ciphertext, ciphertextSize);
        return CryptResult::Ok(ciphertextSize);
    }
    
    size_t outPos = 0;
    PendingSeiInfo currentSei;
    bool havePendingSei = false;
    
    for (size_t nalIdx = 0; nalIdx < nalUnits.size(); nalIdx++) {
        const auto& nal = nalUnits[nalIdx];
        size_t nalEnd = (nalIdx + 1 < nalUnits.size()) ? 
                        nalUnits[nalIdx + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        // Check if this is an SEI NAL
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        if (headerPos >= ciphertextSize) continue;
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = false;
        if (isH265) {
            uint8_t nalType = (nalByte >> 1) & 0x3F;
            isSei = (nalType == 39 || nalType == 40);
        } else {
            uint8_t nalType = nalByte & 0x1F;
            isSei = (nalType == 6);
        }
        
        if (isSei) {
            if (ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, currentSei)) {
                havePendingSei = true;
                _pendingSeis[currentSei.seqNum] = currentSei;
            } else {
                // Not our SEI, copy it
                if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
                memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
                outPos += nalTotalSize;
            }
            continue;
        }
        
        if (nal.should_encrypt && havePendingSei && nalContentSize > 0) {
            // Copy NAL header
            if (outPos + nal.header_size > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            // Decrypt payload using AES-CTR
            if (outPos + nalContentSize > plaintextMaxSize) return CryptResult::Failed();
            if (!DecryptCtr(ciphertext + nal.start_offset + nal.header_size,
                           plaintext + outPos, nalContentSize, currentSei.iv.data())) {
                // Decryption failed - copy as-is
                memcpy(plaintext + outPos, 
                       ciphertext + nal.start_offset + nal.header_size, nalContentSize);
            }
            outPos += nalContentSize;
            
            havePendingSei = false;
        } else {
            // Copy NAL unchanged (SPS/PPS/VPS or unmatched)
            if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    // Clean up old pending SEIs
    while (_pendingSeis.size() > 100) {
        _pendingSeis.erase(_pendingSeis.begin());
    }
    
    return CryptResult::Ok(outPos);
}

// ==================== GOST 28147-89 Cryptor ====================

Gost28147Cryptor::Gost28147Cryptor() {}
Gost28147Cryptor::~Gost28147Cryptor() {}

void Gost28147Cryptor::SetKey(const std::vector<uint8_t>& key) {
    _key = NormalizeKey(key);
}

CryptResult Gost28147Cryptor::EncryptAudio(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    size_t requiredSize = GetMaxAudioCiphertextSize(plaintextSize);
    if (ciphertextMaxSize < requiredSize) return CryptResult::Failed();
    
    uint8_t nonce[kNonceSize];
    RAND_bytes(nonce, kNonceSize);
    
    ciphertext[0] = kAudioMagic;
    memcpy(ciphertext + 1, nonce, kNonceSize);
    
    Gost28147::ctrEncrypt(_key.data(), nonce, 0, plaintext, ciphertext + 1 + kNonceSize, plaintextSize);
    
    // Checksum over encrypted data
    uint32_t checksum = 0;
    for (size_t i = 0; i < plaintextSize; i++) {
        checksum ^= (static_cast<uint32_t>(ciphertext[1 + kNonceSize + i]) << ((i % 4) * 8));
    }
    
    size_t checksumOffset = 1 + kNonceSize + plaintextSize;
    ciphertext[checksumOffset + 0] = checksum & 0xFF;
    ciphertext[checksumOffset + 1] = (checksum >> 8) & 0xFF;
    ciphertext[checksumOffset + 2] = (checksum >> 16) & 0xFF;
    ciphertext[checksumOffset + 3] = (checksum >> 24) & 0xFF;
    
    return CryptResult::Ok(requiredSize);
}

// GOST WriteSeiNal
size_t Gost28147Cryptor::WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum,
                                      const uint8_t* nonce, uint32_t checksum, bool isH265) {
    // SEI payload: UUID(16) + seqNum(4) + magic(1) + nonce(8) + checksum(4) + trailing(1)
    uint8_t rawPayload[48];
    size_t rawPos = 0;
    
    memcpy(rawPayload + rawPos, kSeiUuid, 16);
    rawPos += 16;
    
    rawPayload[rawPos++] = (seqNum >> 24) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 16) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 8) & 0xFF;
    rawPayload[rawPos++] = seqNum & 0xFF;
    
    rawPayload[rawPos++] = kVideoMagic;
    
    memcpy(rawPayload + rawPos, nonce, kNonceSize);
    rawPos += kNonceSize;
    
    rawPayload[rawPos++] = (checksum >> 24) & 0xFF;
    rawPayload[rawPos++] = (checksum >> 16) & 0xFF;
    rawPayload[rawPos++] = (checksum >> 8) & 0xFF;
    rawPayload[rawPos++] = checksum & 0xFF;
    
    rawPayload[rawPos++] = 0x80;  // RBSP trailing
    
    size_t escapedPayloadSize = CalculateEscapedSize(rawPayload, rawPos);
    size_t seiPayloadSize = 16 + 4 + 1 + kNonceSize + kChecksumSize;
    size_t headerSize = 4 + (isH265 ? 2 : 1) + 1 + (seiPayloadSize > 127 ? 2 : 1);
    size_t totalSize = headerSize + escapedPayloadSize;
    
    if (totalSize > maxSize) return 0;
    
    size_t pos = 0;
    output[pos++] = 0x00; output[pos++] = 0x00; output[pos++] = 0x00; output[pos++] = 0x01;
    
    if (isH265) { output[pos++] = 0x4E; output[pos++] = 0x01; }
    else { output[pos++] = 0x06; }
    
    output[pos++] = 0x05;
    if (seiPayloadSize > 127) {
        output[pos++] = 0xFF;
        output[pos++] = static_cast<uint8_t>(seiPayloadSize - 127);
    } else {
        output[pos++] = static_cast<uint8_t>(seiPayloadSize);
    }
    
    size_t written = WriteWithEmulationPrevention(rawPayload, rawPos, output + pos, maxSize - pos);
    if (written == 0) return 0;
    
    return pos + written;
}

bool Gost28147Cryptor::ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info) {
    if (size < 35) return false;
    
    size_t pos = 0;
    if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) pos = 4;
    else if (data[0] == 0 && data[1] == 0 && data[2] == 1) pos = 3;
    else return false;
    
    uint8_t nalByte = data[pos];
    if ((nalByte & 0x80) != 0) return false;
    
    uint8_t h264Type = nalByte & 0x1F;
    uint8_t h265Type = (nalByte >> 1) & 0x3F;
    if (h264Type == 6) pos += 1;
    else if (h265Type == 39 || h265Type == 40) pos += 2;
    else return false;
    
    if (pos >= size || data[pos] != 0x05) return false;
    pos++;
    
    size_t payloadSize = 0;
    while (pos < size && data[pos] == 0xFF) { payloadSize += 255; pos++; }
    if (pos >= size) return false;
    payloadSize += data[pos++];
    
    if (payloadSize < 16 + 4 + 1 + kNonceSize + kChecksumSize) return false;
    
    size_t remainingData = size - pos;
    if (remainingData < payloadSize) return false;
    
    uint8_t deescaped[64];
    size_t deescapedSize = ReadWithEmulationPreventionRemoval(data + pos, remainingData, deescaped, sizeof(deescaped));
    if (deescapedSize < payloadSize) return false;
    
    size_t p = 0;
    if (memcmp(deescaped + p, kSeiUuid, 16) != 0) return false;
    p += 16;
    
    info.seqNum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                  (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                  (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                  static_cast<uint32_t>(deescaped[p + 3]);
    p += 4;
    
    info.magic = deescaped[p++];
    if (info.magic != kVideoMagic) return false;
    
    memcpy(info.nonce, deescaped + p, kNonceSize);
    p += kNonceSize;
    
    info.checksum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                    (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                    (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                    static_cast<uint32_t>(deescaped[p + 3]);
    
    return true;
}

CryptResult Gost28147Cryptor::EncryptVideo(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    bool isH265 = DetectH265(plaintext, plaintextSize);
    auto nalUnits = FindNalUnits(plaintext, plaintextSize, isH265);
    
    if (nalUnits.empty()) {
        if (ciphertextMaxSize < plaintextSize) return CryptResult::Failed();
        memcpy(ciphertext, plaintext, plaintextSize);
        return CryptResult::Ok(plaintextSize);
    }
    
    size_t outPos = 0;
    
    for (size_t nalIdx = 0; nalIdx < nalUnits.size(); nalIdx++) {
        const auto& nal = nalUnits[nalIdx];
        size_t nalEnd = (nalIdx + 1 < nalUnits.size()) ? nalUnits[nalIdx + 1].start_offset : plaintextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        if (nal.should_encrypt && nalContentSize > 0) {
            // Generate nonce and encrypt
            uint8_t nonce[kNonceSize];
            RAND_bytes(nonce, kNonceSize);
            
            // Encrypt payload to temp buffer
            std::vector<uint8_t> encryptedPayload(nalContentSize);
            Gost28147::ctrEncrypt(_key.data(), nonce, 0,
                plaintext + nal.start_offset + nal.header_size,
                encryptedPayload.data(), nalContentSize);
            
            // Compute checksum of encrypted data
            uint32_t checksum = 0;
            for (size_t i = 0; i < nalContentSize; i++) {
                checksum ^= (static_cast<uint32_t>(encryptedPayload[i]) << ((i % 4) * 8));
            }
            
            // Write SEI NAL first
            uint32_t seqNum = _videoSeqNum++;
            size_t seiSize = WriteSeiNal(ciphertext + outPos, ciphertextMaxSize - outPos, 
                                         seqNum, nonce, checksum, isH265);
            if (seiSize == 0) return CryptResult::Failed();
            outPos += seiSize;
            
            // Copy NAL header
            if (outPos + nal.header_size > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            // Copy encrypted payload
            if (outPos + nalContentSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, encryptedPayload.data(), nalContentSize);
            outPos += nalContentSize;
        } else {
            // Copy NAL unchanged
            if (outPos + nalTotalSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    return CryptResult::Ok(outPos);
}

size_t Gost28147Cryptor::GetMaxAudioCiphertextSize(size_t plaintextSize) const {
    return 1 + kNonceSize + plaintextSize + kChecksumSize;
}

size_t Gost28147Cryptor::GetMaxVideoCiphertextSize(size_t plaintextSize) const {
    // Per-NAL: max 32 NALs * (3 + 13) = 512 bytes overhead
    return (plaintextSize * 2) + 32 * (3 + 1 + kNonceSize + kChecksumSize);
}

int Gost28147Cryptor::TryFindAudioKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    if (ciphertextSize < 1 + kNonceSize + kChecksumSize) return -1;
    
    const uint8_t* encryptedData = ciphertext + 1 + kNonceSize;
    size_t encryptedLen = ciphertextSize - 1 - kNonceSize - kChecksumSize;
    
    uint32_t storedChecksum = 
        static_cast<uint32_t>(ciphertext[ciphertextSize - 4]) |
        (static_cast<uint32_t>(ciphertext[ciphertextSize - 3]) << 8) |
        (static_cast<uint32_t>(ciphertext[ciphertextSize - 2]) << 16) |
        (static_cast<uint32_t>(ciphertext[ciphertextSize - 1]) << 24);
    
    for (size_t i = 0; i < keys.size(); i++) {
        auto key = NormalizeKey(keys[i]);
        
        // Verify checksum over encrypted data
        uint32_t checksum = 0;
        for (size_t j = 0; j < encryptedLen; j++) {
            checksum ^= (static_cast<uint32_t>(encryptedData[j]) << ((j % 4) * 8));
        }
        
        if (checksum == storedChecksum) {
            _key = key;
            return static_cast<int>(i);
        }
    }
    
    return -1;
}

int Gost28147Cryptor::TryFindVideoKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    // SEI-based: find SEI with our UUID, then verify checksum on following NAL
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    PendingSeiInfo seiInfo;
    size_t encryptedNalIdx = SIZE_MAX;
    
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = false;
        if (isH265) {
            isSei = (((nalByte >> 1) & 0x3F) == 39 || ((nalByte >> 1) & 0x3F) == 40);
        } else {
            isSei = ((nalByte & 0x1F) == 6);
        }
        
        if (isSei && ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, seiInfo)) {
            for (size_t j = i + 1; j < nalUnits.size(); j++) {
                if (nalUnits[j].should_encrypt) {
                    encryptedNalIdx = j;
                    break;
                }
            }
            break;
        }
    }
    
    if (encryptedNalIdx == SIZE_MAX) return -1;
    
    const auto& nal = nalUnits[encryptedNalIdx];
    size_t nalEnd = (encryptedNalIdx + 1 < nalUnits.size()) ? 
                    nalUnits[encryptedNalIdx + 1].start_offset : ciphertextSize;
    size_t nalContentSize = nalEnd - nal.start_offset - nal.header_size;
    
    // Verify checksum over encrypted payload
    uint32_t checksum = 0;
    for (size_t j = 0; j < nalContentSize; j++) {
        checksum ^= (static_cast<uint32_t>(ciphertext[nal.start_offset + nal.header_size + j]) << ((j % 4) * 8));
    }
    
    if (checksum == seiInfo.checksum && !keys.empty()) {
        _key = NormalizeKey(keys[0]);
        return 0;
    }
    
    return -1;
}

CryptResult Gost28147Cryptor::DecryptAudio(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    if (ciphertextSize < 1 + kNonceSize + kChecksumSize) return CryptResult::Failed();
    
    const uint8_t* nonce = ciphertext + 1;
    const uint8_t* encryptedData = ciphertext + 1 + kNonceSize;
    size_t encryptedLen = ciphertextSize - 1 - kNonceSize - kChecksumSize;
    
    if (plaintextMaxSize < encryptedLen) return CryptResult::Failed();
    
    Gost28147::ctrEncrypt(_key.data(), nonce, 0, encryptedData, plaintext, encryptedLen);
    
    return CryptResult::Ok(encryptedLen);
}

CryptResult Gost28147Cryptor::DecryptVideo(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    if (nalUnits.empty()) {
        if (plaintextMaxSize < ciphertextSize) return CryptResult::Failed();
        memcpy(plaintext, ciphertext, ciphertextSize);
        return CryptResult::Ok(ciphertextSize);
    }
    
    size_t outPos = 0;
    PendingSeiInfo currentSei;
    bool havePendingSei = false;
    
    for (size_t nalIdx = 0; nalIdx < nalUnits.size(); nalIdx++) {
        const auto& nal = nalUnits[nalIdx];
        size_t nalEnd = (nalIdx + 1 < nalUnits.size()) ? nalUnits[nalIdx + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        // Check if SEI
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = false;
        if (isH265) {
            isSei = (((nalByte >> 1) & 0x3F) == 39 || ((nalByte >> 1) & 0x3F) == 40);
        } else {
            isSei = ((nalByte & 0x1F) == 6);
        }
        
        if (isSei) {
            if (ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, currentSei)) {
                havePendingSei = true;
                _pendingSeis[currentSei.seqNum] = currentSei;
            } else {
                // Not our SEI, copy it
                if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
                memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
                outPos += nalTotalSize;
            }
            continue;
        }
        
        if (nal.should_encrypt && havePendingSei && nalContentSize > 0) {
            // Copy NAL header
            if (outPos + nal.header_size > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            // Decrypt payload
            if (outPos + nalContentSize > plaintextMaxSize) return CryptResult::Failed();
            Gost28147::ctrEncrypt(_key.data(), currentSei.nonce, 0,
                ciphertext + nal.start_offset + nal.header_size,
                plaintext + outPos,
                nalContentSize);
            outPos += nalContentSize;
            
            havePendingSei = false;
        } else {
            // Copy NAL unchanged
            if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    while (_pendingSeis.size() > 100) {
        _pendingSeis.erase(_pendingSeis.begin());
    }
    
    return CryptResult::Ok(outPos);
}

// ==================== AES-256 LITE Cryptor ====================

Aes256LiteCryptor::Aes256LiteCryptor() {
    _ctx = EVP_CIPHER_CTX_new();
}

Aes256LiteCryptor::~Aes256LiteCryptor() {
    if (_ctx) EVP_CIPHER_CTX_free(_ctx);
}

void Aes256LiteCryptor::SetKey(const std::vector<uint8_t>& key) {
    _key = NormalizeKey(key);
}

// AES-LITE SEI methods (same format as full AES)
size_t Aes256LiteCryptor::WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum,
                                       const uint8_t* iv, const uint8_t* tag, bool isH265) {
    uint8_t rawPayload[64];
    size_t rawPos = 0;
    
    memcpy(rawPayload + rawPos, kSeiUuid, 16);
    rawPos += 16;
    
    rawPayload[rawPos++] = (seqNum >> 24) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 16) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 8) & 0xFF;
    rawPayload[rawPos++] = seqNum & 0xFF;
    
    rawPayload[rawPos++] = kVideoMagic;
    
    memcpy(rawPayload + rawPos, iv, kIvSize);
    rawPos += kIvSize;
    
    memcpy(rawPayload + rawPos, tag, kTagSize);
    rawPos += kTagSize;
    
    rawPayload[rawPos++] = 0x80;
    
    size_t escapedPayloadSize = CalculateEscapedSize(rawPayload, rawPos);
    size_t seiPayloadSize = 16 + 4 + 1 + kIvSize + kTagSize;
    size_t headerSize = 4 + (isH265 ? 2 : 1) + 1 + (seiPayloadSize > 127 ? 2 : 1);
    size_t totalSize = headerSize + escapedPayloadSize;
    
    if (totalSize > maxSize) return 0;
    
    size_t pos = 0;
    output[pos++] = 0x00; output[pos++] = 0x00; output[pos++] = 0x00; output[pos++] = 0x01;
    
    if (isH265) { output[pos++] = 0x4E; output[pos++] = 0x01; }
    else { output[pos++] = 0x06; }
    
    output[pos++] = 0x05;
    if (seiPayloadSize > 127) {
        output[pos++] = 0xFF;
        output[pos++] = static_cast<uint8_t>(seiPayloadSize - 127);
    } else {
        output[pos++] = static_cast<uint8_t>(seiPayloadSize);
    }
    
    size_t written = WriteWithEmulationPrevention(rawPayload, rawPos, output + pos, maxSize - pos);
    if (written == 0) return 0;
    
    return pos + written;
}

bool Aes256LiteCryptor::ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info) {
    if (size < 55) return false;
    
    size_t pos = 0;
    if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) pos = 4;
    else if (data[0] == 0 && data[1] == 0 && data[2] == 1) pos = 3;
    else return false;
    
    uint8_t nalByte = data[pos];
    if ((nalByte & 0x80) != 0) return false;
    
    uint8_t h264Type = nalByte & 0x1F;
    uint8_t h265Type = (nalByte >> 1) & 0x3F;
    if (h264Type == 6) pos += 1;
    else if (h265Type == 39 || h265Type == 40) pos += 2;
    else return false;
    
    if (pos >= size || data[pos] != 0x05) return false;
    pos++;
    
    size_t payloadSize = 0;
    while (pos < size && data[pos] == 0xFF) { payloadSize += 255; pos++; }
    if (pos >= size) return false;
    payloadSize += data[pos++];
    
    if (payloadSize < 16 + 4 + 1 + kIvSize + kTagSize) return false;
    
    size_t remainingData = size - pos;
    if (remainingData < payloadSize) return false;
    
    uint8_t deescaped[80];
    size_t deescapedSize = ReadWithEmulationPreventionRemoval(data + pos, remainingData, deescaped, sizeof(deescaped));
    if (deescapedSize < payloadSize) return false;
    
    size_t p = 0;
    if (memcmp(deescaped + p, kSeiUuid, 16) != 0) return false;
    p += 16;
    
    info.seqNum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                  (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                  (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                  static_cast<uint32_t>(deescaped[p + 3]);
    p += 4;
    
    info.magic = deescaped[p++];
    if (info.magic != kVideoMagic) return false;
    
    info.iv.resize(kIvSize);
    memcpy(info.iv.data(), deescaped + p, kIvSize);
    p += kIvSize;
    
    info.tag.resize(kTagSize);
    memcpy(info.tag.data(), deescaped + p, kTagSize);
    
    return true;
}

CryptResult Aes256LiteCryptor::EncryptAudio(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    size_t requiredSize = GetMaxAudioCiphertextSize(plaintextSize);
    if (ciphertextMaxSize < requiredSize) return CryptResult::Failed();
    
    uint8_t iv[kIvSize];
    uint8_t xorKey[kXorKeySize];
    RAND_bytes(iv, kIvSize);
    RAND_bytes(xorKey, kXorKeySize);
    
    ciphertext[0] = kAudioMagic;
    memcpy(ciphertext + 1, iv, kIvSize);
    
    size_t headSize = std::min(kEncryptedHeadSize, plaintextSize);
    size_t restSize = plaintextSize > headSize ? plaintextSize - headSize : 0;
    
    // Prepare HEAD + XOR_KEY
    std::vector<uint8_t> toEncrypt(headSize + kXorKeySize);
    memcpy(toEncrypt.data(), plaintext, headSize);
    memcpy(toEncrypt.data() + headSize, xorKey, kXorKeySize);
    
    EVP_CIPHER_CTX_reset(_ctx);
    if (!EVP_EncryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, _key.data(), iv)) {
        return CryptResult::Failed();
    }
    
    int outLen = 0;
    if (!EVP_EncryptUpdate(_ctx, ciphertext + 1 + kIvSize, &outLen, toEncrypt.data(), toEncrypt.size())) {
        return CryptResult::Failed();
    }
    
    int finalLen = 0;
    if (!EVP_EncryptFinal_ex(_ctx, ciphertext + 1 + kIvSize + outLen, &finalLen)) {
        return CryptResult::Failed();
    }
    
    size_t encPartSize = outLen + finalLen;
    size_t xorOffset = 1 + kIvSize + encPartSize;
    
    for (size_t i = 0; i < restSize; i++) {
        ciphertext[xorOffset + i] = plaintext[headSize + i] ^ xorKey[i % kXorKeySize];
    }
    
    size_t tagOffset = xorOffset + restSize;
    if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, ciphertext + tagOffset)) {
        return CryptResult::Failed();
    }
    
    return CryptResult::Ok(tagOffset + kTagSize);
}

CryptResult Aes256LiteCryptor::EncryptVideo(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    bool isH265 = DetectH265(plaintext, plaintextSize);
    auto nalUnits = FindNalUnits(plaintext, plaintextSize, isH265);
    
    if (nalUnits.empty()) {
        if (ciphertextMaxSize < plaintextSize) return CryptResult::Failed();
        memcpy(ciphertext, plaintext, plaintextSize);
        return CryptResult::Ok(plaintextSize);
    }
    
    size_t outPos = 0;
    
    for (size_t nalIdx = 0; nalIdx < nalUnits.size(); nalIdx++) {
        const auto& nal = nalUnits[nalIdx];
        size_t nalEnd = (nalIdx + 1 < nalUnits.size()) ? nalUnits[nalIdx + 1].start_offset : plaintextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        if (nal.should_encrypt && nalContentSize > 0) {
            uint8_t iv[kIvSize];
            RAND_bytes(iv, kIvSize);
            
            // Encrypt payload
            std::vector<uint8_t> encryptedPayload(nalContentSize);
            uint8_t counter[16] = {0};
            memcpy(counter, iv, kIvSize);
            
            EVP_CIPHER_CTX* ctr_ctx = EVP_CIPHER_CTX_new();
            EVP_EncryptInit_ex(ctr_ctx, EVP_aes_256_ctr(), nullptr, _key.data(), counter);
            int encLen;
            EVP_EncryptUpdate(ctr_ctx, encryptedPayload.data(), &encLen,
                plaintext + nal.start_offset + nal.header_size, nalContentSize);
            EVP_CIPHER_CTX_free(ctr_ctx);
            
            // Compute GMAC
            uint8_t tag[kTagSize];
            EVP_CIPHER_CTX_reset(_ctx);
            EVP_EncryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
            EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, kIvSize, nullptr);
            EVP_EncryptInit_ex(_ctx, nullptr, nullptr, _key.data(), iv);
            int outLen = 0;
            EVP_EncryptUpdate(_ctx, nullptr, &outLen, encryptedPayload.data(), nalContentSize);
            EVP_EncryptFinal_ex(_ctx, nullptr, &outLen);
            EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, tag);
            
            // Write SEI NAL
            uint32_t seqNum = _videoSeqNum++;
            size_t seiSize = WriteSeiNal(ciphertext + outPos, ciphertextMaxSize - outPos, seqNum, iv, tag, isH265);
            if (seiSize == 0) return CryptResult::Failed();
            outPos += seiSize;
            
            // Copy NAL header
            if (outPos + nal.header_size > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            // Copy encrypted payload
            if (outPos + nalContentSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, encryptedPayload.data(), nalContentSize);
            outPos += nalContentSize;
        } else {
            if (outPos + nalTotalSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    return CryptResult::Ok(outPos);
}

size_t Aes256LiteCryptor::GetMaxAudioCiphertextSize(size_t plaintextSize) const {
    size_t headSize = std::min(kEncryptedHeadSize, plaintextSize);
    size_t restSize = plaintextSize > headSize ? plaintextSize - headSize : 0;
    return 1 + kIvSize + (headSize + kXorKeySize) + restSize + kTagSize;
}

size_t Aes256LiteCryptor::GetMaxVideoCiphertextSize(size_t plaintextSize) const {
    // Per-NAL: max 32 NALs * 32 bytes overhead
    return (plaintextSize * 2) + 32 * (3 + 1 + kIvSize + kTagSize);
}

int Aes256LiteCryptor::TryFindAudioKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    if (ciphertextSize < 1 + kIvSize + kXorKeySize + kTagSize) return -1;
    
    const uint8_t* iv = ciphertext + 1;
    const uint8_t* tag = ciphertext + ciphertextSize - kTagSize;
    
    size_t headSize = kEncryptedHeadSize;
    size_t encPartSize = headSize + kXorKeySize;
    size_t minSize = 1 + kIvSize + encPartSize + kTagSize;
    
    if (ciphertextSize < minSize) return -1;
    
    const uint8_t* encPart = ciphertext + 1 + kIvSize;
    
    for (size_t i = 0; i < keys.size(); i++) {
        _key = NormalizeKey(keys[i]);
        
        EVP_CIPHER_CTX_reset(_ctx);
        if (!EVP_DecryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, _key.data(), iv)) continue;
        
        std::vector<uint8_t> decrypted(encPartSize);
        int outLen = 0;
        if (!EVP_DecryptUpdate(_ctx, decrypted.data(), &outLen, encPart, encPartSize)) continue;
        if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, kTagSize, const_cast<uint8_t*>(tag))) continue;
        
        int finalLen = 0;
        if (EVP_DecryptFinal_ex(_ctx, decrypted.data() + outLen, &finalLen) > 0) {
            return static_cast<int>(i);
        }
    }
    
    _key.clear();
    return -1;
}

int Aes256LiteCryptor::TryFindVideoKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    PendingSeiInfo seiInfo;
    size_t encryptedNalIdx = SIZE_MAX;
    
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = isH265 ? (((nalByte >> 1) & 0x3F) == 39 || ((nalByte >> 1) & 0x3F) == 40) 
                            : ((nalByte & 0x1F) == 6);
        
        if (isSei && ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, seiInfo)) {
            for (size_t j = i + 1; j < nalUnits.size(); j++) {
                if (nalUnits[j].should_encrypt) {
                    encryptedNalIdx = j;
                    break;
                }
            }
            break;
        }
    }
    
    if (encryptedNalIdx == SIZE_MAX) return -1;
    
    const auto& nal = nalUnits[encryptedNalIdx];
    size_t nalEnd = (encryptedNalIdx + 1 < nalUnits.size()) ? nalUnits[encryptedNalIdx + 1].start_offset : ciphertextSize;
    size_t nalContentSize = nalEnd - nal.start_offset - nal.header_size;
    
    for (size_t i = 0; i < keys.size(); i++) {
        _key = NormalizeKey(keys[i]);
        
        EVP_CIPHER_CTX_reset(_ctx);
        EVP_EncryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
        EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_IVLEN, kIvSize, nullptr);
        EVP_EncryptInit_ex(_ctx, nullptr, nullptr, _key.data(), seiInfo.iv.data());
        int outLen = 0;
        EVP_EncryptUpdate(_ctx, nullptr, &outLen, ciphertext + nal.start_offset + nal.header_size, nalContentSize);
        EVP_EncryptFinal_ex(_ctx, nullptr, &outLen);
        
        uint8_t computed_tag[kTagSize];
        EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_GET_TAG, kTagSize, computed_tag);
        
        if (memcmp(seiInfo.tag.data(), computed_tag, kTagSize) == 0) {
            return static_cast<int>(i);
        }
    }
    
    _key.clear();
    return -1;
}

CryptResult Aes256LiteCryptor::DecryptAudio(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    if (ciphertextSize < 1 + kIvSize + kXorKeySize + kTagSize) return CryptResult::Failed();
    
    const uint8_t* iv = ciphertext + 1;
    const uint8_t* tag = ciphertext + ciphertextSize - kTagSize;
    
    size_t headSize = kEncryptedHeadSize;
    size_t encPartSize = headSize + kXorKeySize;
    size_t minSize = 1 + kIvSize + encPartSize + kTagSize;
    
    if (ciphertextSize < minSize) return CryptResult::Failed();
    
    size_t restSize = ciphertextSize - minSize;
    size_t plaintextSize = headSize + restSize;
    
    if (plaintextMaxSize < plaintextSize) return CryptResult::Failed();
    
    const uint8_t* encPart = ciphertext + 1 + kIvSize;
    const uint8_t* xorPart = ciphertext + 1 + kIvSize + encPartSize;
    
    EVP_CIPHER_CTX_reset(_ctx);
    if (!EVP_DecryptInit_ex(_ctx, EVP_aes_256_gcm(), nullptr, _key.data(), iv)) {
        return CryptResult::Failed();
    }
    
    std::vector<uint8_t> decrypted(encPartSize);
    int outLen = 0;
    if (!EVP_DecryptUpdate(_ctx, decrypted.data(), &outLen, encPart, encPartSize)) {
        return CryptResult::Failed();
    }
    
    if (!EVP_CIPHER_CTX_ctrl(_ctx, EVP_CTRL_GCM_SET_TAG, kTagSize, const_cast<uint8_t*>(tag))) {
        return CryptResult::Failed();
    }
    
    int finalLen = 0;
    if (EVP_DecryptFinal_ex(_ctx, decrypted.data() + outLen, &finalLen) <= 0) {
        return CryptResult::Failed();
    }
    
    memcpy(plaintext, decrypted.data(), headSize);
    const uint8_t* xorKey = decrypted.data() + headSize;
    
    for (size_t i = 0; i < restSize; i++) {
        plaintext[headSize + i] = xorPart[i] ^ xorKey[i % kXorKeySize];
    }
    
    return CryptResult::Ok(plaintextSize);
}

CryptResult Aes256LiteCryptor::DecryptVideo(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    if (nalUnits.empty()) {
        if (plaintextMaxSize < ciphertextSize) return CryptResult::Failed();
        memcpy(plaintext, ciphertext, ciphertextSize);
        return CryptResult::Ok(ciphertextSize);
    }
    
    size_t outPos = 0;
    PendingSeiInfo currentSei;
    bool havePendingSei = false;
    
    for (size_t nalIdx = 0; nalIdx < nalUnits.size(); nalIdx++) {
        const auto& nal = nalUnits[nalIdx];
        size_t nalEnd = (nalIdx + 1 < nalUnits.size()) ? nalUnits[nalIdx + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = isH265 ? (((nalByte >> 1) & 0x3F) == 39 || ((nalByte >> 1) & 0x3F) == 40) 
                            : ((nalByte & 0x1F) == 6);
        
        if (isSei) {
            if (ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, currentSei)) {
                havePendingSei = true;
                _pendingSeis[currentSei.seqNum] = currentSei;
            } else {
                if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
                memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
                outPos += nalTotalSize;
            }
            continue;
        }
        
        if (nal.should_encrypt && havePendingSei && nalContentSize > 0) {
            if (outPos + nal.header_size > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            if (outPos + nalContentSize > plaintextMaxSize) return CryptResult::Failed();
            
            uint8_t counter[16] = {0};
            memcpy(counter, currentSei.iv.data(), kIvSize);
            
            EVP_CIPHER_CTX* ctr_ctx = EVP_CIPHER_CTX_new();
            EVP_DecryptInit_ex(ctr_ctx, EVP_aes_256_ctr(), nullptr, _key.data(), counter);
            int decLen;
            EVP_DecryptUpdate(ctr_ctx, plaintext + outPos, &decLen,
                ciphertext + nal.start_offset + nal.header_size, nalContentSize);
            EVP_CIPHER_CTX_free(ctr_ctx);
            outPos += nalContentSize;
            
            havePendingSei = false;
        } else {
            if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    while (_pendingSeis.size() > 100) {
        _pendingSeis.erase(_pendingSeis.begin());
    }
    
    return CryptResult::Ok(outPos);
}

// ==================== GOST LITE Cryptor ====================

GostLiteCryptor::GostLiteCryptor() {}
GostLiteCryptor::~GostLiteCryptor() {}

void GostLiteCryptor::SetKey(const std::vector<uint8_t>& key) {
    _key = NormalizeKey(key);
}

// GOST-LITE SEI methods (same format as full GOST)
size_t GostLiteCryptor::WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum,
                                     const uint8_t* nonce, uint32_t checksum, bool isH265) {
    uint8_t rawPayload[48];
    size_t rawPos = 0;
    
    memcpy(rawPayload + rawPos, kSeiUuid, 16);
    rawPos += 16;
    
    rawPayload[rawPos++] = (seqNum >> 24) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 16) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 8) & 0xFF;
    rawPayload[rawPos++] = seqNum & 0xFF;
    
    rawPayload[rawPos++] = kVideoMagic;
    
    memcpy(rawPayload + rawPos, nonce, kNonceSize);
    rawPos += kNonceSize;
    
    rawPayload[rawPos++] = (checksum >> 24) & 0xFF;
    rawPayload[rawPos++] = (checksum >> 16) & 0xFF;
    rawPayload[rawPos++] = (checksum >> 8) & 0xFF;
    rawPayload[rawPos++] = checksum & 0xFF;
    
    rawPayload[rawPos++] = 0x80;
    
    size_t escapedPayloadSize = CalculateEscapedSize(rawPayload, rawPos);
    size_t seiPayloadSize = 16 + 4 + 1 + kNonceSize + kChecksumSize;
    size_t headerSize = 4 + (isH265 ? 2 : 1) + 1 + (seiPayloadSize > 127 ? 2 : 1);
    size_t totalSize = headerSize + escapedPayloadSize;
    
    if (totalSize > maxSize) return 0;
    
    size_t pos = 0;
    output[pos++] = 0x00; output[pos++] = 0x00; output[pos++] = 0x00; output[pos++] = 0x01;
    
    if (isH265) { output[pos++] = 0x4E; output[pos++] = 0x01; }
    else { output[pos++] = 0x06; }
    
    output[pos++] = 0x05;
    if (seiPayloadSize > 127) {
        output[pos++] = 0xFF;
        output[pos++] = static_cast<uint8_t>(seiPayloadSize - 127);
    } else {
        output[pos++] = static_cast<uint8_t>(seiPayloadSize);
    }
    
    size_t written = WriteWithEmulationPrevention(rawPayload, rawPos, output + pos, maxSize - pos);
    if (written == 0) return 0;
    
    return pos + written;
}

bool GostLiteCryptor::ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info) {
    if (size < 35) return false;
    
    size_t pos = 0;
    if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) pos = 4;
    else if (data[0] == 0 && data[1] == 0 && data[2] == 1) pos = 3;
    else return false;
    
    uint8_t nalByte = data[pos];
    if ((nalByte & 0x80) != 0) return false;
    
    uint8_t h264Type = nalByte & 0x1F;
    uint8_t h265Type = (nalByte >> 1) & 0x3F;
    if (h264Type == 6) pos += 1;
    else if (h265Type == 39 || h265Type == 40) pos += 2;
    else return false;
    
    if (pos >= size || data[pos] != 0x05) return false;
    pos++;
    
    size_t payloadSize = 0;
    while (pos < size && data[pos] == 0xFF) { payloadSize += 255; pos++; }
    if (pos >= size) return false;
    payloadSize += data[pos++];
    
    if (payloadSize < 16 + 4 + 1 + kNonceSize + kChecksumSize) return false;
    
    size_t remainingData = size - pos;
    if (remainingData < payloadSize) return false;
    
    uint8_t deescaped[64];
    size_t deescapedSize = ReadWithEmulationPreventionRemoval(data + pos, remainingData, deescaped, sizeof(deescaped));
    if (deescapedSize < payloadSize) return false;
    
    size_t p = 0;
    if (memcmp(deescaped + p, kSeiUuid, 16) != 0) return false;
    p += 16;
    
    info.seqNum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                  (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                  (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                  static_cast<uint32_t>(deescaped[p + 3]);
    p += 4;
    
    info.magic = deescaped[p++];
    if (info.magic != kVideoMagic) return false;
    
    memcpy(info.nonce, deescaped + p, kNonceSize);
    p += kNonceSize;
    
    info.checksum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                    (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                    (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                    static_cast<uint32_t>(deescaped[p + 3]);
    
    return true;
}

CryptResult GostLiteCryptor::EncryptAudio(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    size_t requiredSize = GetMaxAudioCiphertextSize(plaintextSize);
    if (ciphertextMaxSize < requiredSize) return CryptResult::Failed();
    
    uint8_t nonce[kNonceSize];
    uint8_t xorKey[kXorKeySize];
    RAND_bytes(nonce, kNonceSize);
    RAND_bytes(xorKey, kXorKeySize);
    
    ciphertext[0] = kAudioMagic;
    memcpy(ciphertext + 1, nonce, kNonceSize);
    
    size_t headSize = std::min(kEncryptedHeadSize, plaintextSize);
    size_t restSize = plaintextSize > headSize ? plaintextSize - headSize : 0;
    
    std::vector<uint8_t> toEncrypt(headSize + kXorKeySize);
    memcpy(toEncrypt.data(), plaintext, headSize);
    memcpy(toEncrypt.data() + headSize, xorKey, kXorKeySize);
    
    size_t encOffset = 1 + kNonceSize;
    Gost28147::ctrEncrypt(_key.data(), nonce, 0, toEncrypt.data(), ciphertext + encOffset, toEncrypt.size());
    
    size_t xorOffset = encOffset + toEncrypt.size();
    for (size_t i = 0; i < restSize; i++) {
        ciphertext[xorOffset + i] = plaintext[headSize + i] ^ xorKey[i % kXorKeySize];
    }
    
    // Checksum over original plaintext
    uint32_t checksum = 0;
    for (size_t i = 0; i < plaintextSize; i++) {
        checksum += plaintext[i];
    }
    
    size_t checksumOffset = xorOffset + restSize;
    ciphertext[checksumOffset + 0] = checksum & 0xFF;
    ciphertext[checksumOffset + 1] = (checksum >> 8) & 0xFF;
    ciphertext[checksumOffset + 2] = (checksum >> 16) & 0xFF;
    ciphertext[checksumOffset + 3] = (checksum >> 24) & 0xFF;
    
    return CryptResult::Ok(checksumOffset + kChecksumSize);
}

CryptResult GostLiteCryptor::EncryptVideo(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    bool isH265 = DetectH265(plaintext, plaintextSize);
    auto nalUnits = FindNalUnits(plaintext, plaintextSize, isH265);
    
    if (nalUnits.empty()) {
        if (ciphertextMaxSize < plaintextSize) return CryptResult::Failed();
        memcpy(ciphertext, plaintext, plaintextSize);
        return CryptResult::Ok(plaintextSize);
    }
    
    size_t outPos = 0;
    
    for (size_t nalIdx = 0; nalIdx < nalUnits.size(); nalIdx++) {
        const auto& nal = nalUnits[nalIdx];
        size_t nalEnd = (nalIdx + 1 < nalUnits.size()) ? nalUnits[nalIdx + 1].start_offset : plaintextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        if (nal.should_encrypt && nalContentSize > 0) {
            uint8_t nonce[kNonceSize];
            RAND_bytes(nonce, kNonceSize);
            
            std::vector<uint8_t> encryptedPayload(nalContentSize);
            Gost28147::ctrEncrypt(_key.data(), nonce, 0,
                plaintext + nal.start_offset + nal.header_size,
                encryptedPayload.data(), nalContentSize);
            
            uint32_t checksum = 0;
            for (size_t i = 0; i < nalContentSize; i++) {
                checksum ^= (static_cast<uint32_t>(encryptedPayload[i]) << ((i % 4) * 8));
            }
            
            uint32_t seqNum = _videoSeqNum++;
            size_t seiSize = WriteSeiNal(ciphertext + outPos, ciphertextMaxSize - outPos, seqNum, nonce, checksum, isH265);
            if (seiSize == 0) return CryptResult::Failed();
            outPos += seiSize;
            
            if (outPos + nal.header_size > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            if (outPos + nalContentSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, encryptedPayload.data(), nalContentSize);
            outPos += nalContentSize;
        } else {
            if (outPos + nalTotalSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    return CryptResult::Ok(outPos);
}

size_t GostLiteCryptor::GetMaxAudioCiphertextSize(size_t plaintextSize) const {
    size_t headSize = std::min(kEncryptedHeadSize, plaintextSize);
    size_t restSize = plaintextSize > headSize ? plaintextSize - headSize : 0;
    return 1 + kNonceSize + (headSize + kXorKeySize) + restSize + kChecksumSize;
}

size_t GostLiteCryptor::GetMaxVideoCiphertextSize(size_t plaintextSize) const {
    // Per-NAL: max 32 NALs * 16 bytes overhead
    return (plaintextSize * 2) + 32 * (3 + 1 + kNonceSize + kChecksumSize);
}

int GostLiteCryptor::TryFindAudioKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    if (ciphertextSize < 1 + kNonceSize + kXorKeySize + kChecksumSize) return -1;
    
    const uint8_t* nonce = ciphertext + 1;
    
    uint32_t storedChecksum = 
        static_cast<uint32_t>(ciphertext[ciphertextSize - 4]) |
        (static_cast<uint32_t>(ciphertext[ciphertextSize - 3]) << 8) |
        (static_cast<uint32_t>(ciphertext[ciphertextSize - 2]) << 16) |
        (static_cast<uint32_t>(ciphertext[ciphertextSize - 1]) << 24);
    
    size_t headSize = kEncryptedHeadSize;
    size_t encPartSize = headSize + kXorKeySize;
    size_t minSize = 1 + kNonceSize + encPartSize + kChecksumSize;
    
    if (ciphertextSize < minSize) return -1;
    
    size_t restSize = ciphertextSize - minSize;
    size_t plaintextSize = headSize + restSize;
    
    const uint8_t* encPart = ciphertext + 1 + kNonceSize;
    const uint8_t* xorPart = ciphertext + 1 + kNonceSize + encPartSize;
    
    for (size_t i = 0; i < keys.size(); i++) {
        auto key = NormalizeKey(keys[i]);
        
        std::vector<uint8_t> decrypted(encPartSize);
        Gost28147::ctrEncrypt(key.data(), nonce, 0, encPart, decrypted.data(), encPartSize);
        
        std::vector<uint8_t> plaintext(plaintextSize);
        memcpy(plaintext.data(), decrypted.data(), headSize);
        const uint8_t* xorKey = decrypted.data() + headSize;
        
        for (size_t j = 0; j < restSize; j++) {
            plaintext[headSize + j] = xorPart[j] ^ xorKey[j % kXorKeySize];
        }
        
        uint32_t checksum = 0;
        for (size_t j = 0; j < plaintextSize; j++) {
            checksum += plaintext[j];
        }
        
        if (checksum == storedChecksum) {
            _key = key;
            return static_cast<int>(i);
        }
    }
    
    return -1;
}

int GostLiteCryptor::TryFindVideoKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    PendingSeiInfo seiInfo;
    size_t encryptedNalIdx = SIZE_MAX;
    
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = isH265 ? (((nalByte >> 1) & 0x3F) == 39 || ((nalByte >> 1) & 0x3F) == 40)
                            : ((nalByte & 0x1F) == 6);
        
        if (isSei && ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, seiInfo)) {
            for (size_t j = i + 1; j < nalUnits.size(); j++) {
                if (nalUnits[j].should_encrypt) {
                    encryptedNalIdx = j;
                    break;
                }
            }
            break;
        }
    }
    
    if (encryptedNalIdx == SIZE_MAX) return -1;
    
    const auto& nal = nalUnits[encryptedNalIdx];
    size_t nalEnd = (encryptedNalIdx + 1 < nalUnits.size()) ? nalUnits[encryptedNalIdx + 1].start_offset : ciphertextSize;
    size_t nalContentSize = nalEnd - nal.start_offset - nal.header_size;
    
    uint32_t checksum = 0;
    for (size_t j = 0; j < nalContentSize; j++) {
        checksum ^= (static_cast<uint32_t>(ciphertext[nal.start_offset + nal.header_size + j]) << ((j % 4) * 8));
    }
    
    if (checksum == seiInfo.checksum && !keys.empty()) {
        _key = NormalizeKey(keys[0]);
        return 0;
    }
    
    return -1;
}

CryptResult GostLiteCryptor::DecryptAudio(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    if (ciphertextSize < 1 + kNonceSize + kXorKeySize + kChecksumSize) return CryptResult::Failed();
    
    const uint8_t* nonce = ciphertext + 1;
    
    size_t headSize = kEncryptedHeadSize;
    size_t encPartSize = headSize + kXorKeySize;
    size_t minSize = 1 + kNonceSize + encPartSize + kChecksumSize;
    
    if (ciphertextSize < minSize) return CryptResult::Failed();
    
    size_t restSize = ciphertextSize - minSize;
    size_t plaintextSize = headSize + restSize;
    
    if (plaintextMaxSize < plaintextSize) return CryptResult::Failed();
    
    const uint8_t* encPart = ciphertext + 1 + kNonceSize;
    const uint8_t* xorPart = ciphertext + 1 + kNonceSize + encPartSize;
    
    std::vector<uint8_t> decrypted(encPartSize);
    Gost28147::ctrEncrypt(_key.data(), nonce, 0, encPart, decrypted.data(), encPartSize);
    
    memcpy(plaintext, decrypted.data(), headSize);
    const uint8_t* xorKey = decrypted.data() + headSize;
    
    for (size_t i = 0; i < restSize; i++) {
        plaintext[headSize + i] = xorPart[i] ^ xorKey[i % kXorKeySize];
    }
    
    return CryptResult::Ok(plaintextSize);
}

CryptResult GostLiteCryptor::DecryptVideo(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    if (nalUnits.empty()) {
        if (plaintextMaxSize < ciphertextSize) return CryptResult::Failed();
        memcpy(plaintext, ciphertext, ciphertextSize);
        return CryptResult::Ok(ciphertextSize);
    }
    
    size_t outPos = 0;
    PendingSeiInfo currentSei;
    bool havePendingSei = false;
    
    for (size_t nalIdx = 0; nalIdx < nalUnits.size(); nalIdx++) {
        const auto& nal = nalUnits[nalIdx];
        size_t nalEnd = (nalIdx + 1 < nalUnits.size()) ? nalUnits[nalIdx + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = isH265 ? (((nalByte >> 1) & 0x3F) == 39 || ((nalByte >> 1) & 0x3F) == 40)
                            : ((nalByte & 0x1F) == 6);
        
        if (isSei) {
            if (ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, currentSei)) {
                havePendingSei = true;
                _pendingSeis[currentSei.seqNum] = currentSei;
            } else {
                if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
                memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
                outPos += nalTotalSize;
            }
            continue;
        }
        
        if (nal.should_encrypt && havePendingSei && nalContentSize > 0) {
            if (outPos + nal.header_size > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            if (outPos + nalContentSize > plaintextMaxSize) return CryptResult::Failed();
            Gost28147::ctrEncrypt(_key.data(), currentSei.nonce, 0,
                ciphertext + nal.start_offset + nal.header_size,
                plaintext + outPos,
                nalContentSize);
            outPos += nalContentSize;
            
            havePendingSei = false;
        } else {
            if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    while (_pendingSeis.size() > 100) {
        _pendingSeis.erase(_pendingSeis.begin());
    }
    
    return CryptResult::Ok(outPos);
}

// ==================== PASSTHROUGH (Debug) ====================

PassthroughCryptor::PassthroughCryptor() {}
PassthroughCryptor::~PassthroughCryptor() {}

void PassthroughCryptor::SetKey(const std::vector<uint8_t>& key) {
    _key = key;
}

uint32_t PassthroughCryptor::ComputeChecksum(const uint8_t* data, size_t size) {
    uint32_t sum = 0;
    for (size_t i = 0; i < size; i++) {
        sum = (sum << 1) | (sum >> 31);  // Rotate left
        sum ^= data[i];
    }
    return sum;
}

CryptResult PassthroughCryptor::EncryptAudio(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    // Format: [MAGIC 1B][DATA][CHECKSUM 4B]
    size_t totalSize = 1 + plaintextSize + kChecksumSize;
    
    if (totalSize > ciphertextMaxSize) return CryptResult::Failed();
    
    // Magic byte first (for detection)
    ciphertext[0] = kAudioMagic;
    
    // Copy plaintext unchanged
    memcpy(ciphertext + 1, plaintext, plaintextSize);
    
    // Add checksum at the end
    uint32_t checksum = ComputeChecksum(plaintext, plaintextSize);
    size_t pos = 1 + plaintextSize;
    ciphertext[pos++] = (checksum >> 24) & 0xFF;
    ciphertext[pos++] = (checksum >> 16) & 0xFF;
    ciphertext[pos++] = (checksum >> 8) & 0xFF;
    ciphertext[pos++] = checksum & 0xFF;
    
    return CryptResult::Ok(totalSize);
}

// Write SEI NAL with our custom trailer
size_t PassthroughCryptor::WriteSeiNal(uint8_t* output, size_t maxSize, 
                                        uint32_t seqNum, uint32_t checksum, bool isH265) {
    // SEI NAL format with emulation prevention:
    // [START_CODE 4B][NAL_HEADER 1-2B][payloadType=5 1B][payloadSize 1-2B]
    // [UUID 16B][SEQ_NUM 4B][MAGIC 1B][CHECKSUM 4B] (with emulation prevention)
    // [RBSP_TRAILING 1B]
    
    // Build raw payload first (needs emulation prevention)
    uint8_t rawPayload[32];  // UUID(16) + seq(4) + magic(1) + checksum(4) + trailing(1) = 26
    size_t rawPos = 0;
    
    // UUID (16 bytes) - start with 0xC1, so no initial 00s
    memcpy(rawPayload + rawPos, kSeiUuid, 16);
    rawPos += 16;
    
    // Sequence number (4 bytes, big-endian)
    rawPayload[rawPos++] = (seqNum >> 24) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 16) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 8) & 0xFF;
    rawPayload[rawPos++] = seqNum & 0xFF;
    
    // Magic byte
    rawPayload[rawPos++] = kVideoMagic;
    
    // Checksum (4 bytes, big-endian)
    rawPayload[rawPos++] = (checksum >> 24) & 0xFF;
    rawPayload[rawPos++] = (checksum >> 16) & 0xFF;
    rawPayload[rawPos++] = (checksum >> 8) & 0xFF;
    rawPayload[rawPos++] = checksum & 0xFF;
    
    // RBSP trailing bits
    rawPayload[rawPos++] = 0x80;
    
    // Calculate escaped size
    size_t escapedPayloadSize = CalculateEscapedSize(rawPayload, rawPos);
    size_t rbspPayloadSize = escapedPayloadSize - 1;  // Exclude trailing byte from SEI payloadSize
    
    size_t headerSize = 4 + (isH265 ? 2 : 1) + 1 + (rbspPayloadSize > 127 ? 2 : 1);
    size_t totalSize = headerSize + escapedPayloadSize;
    
    if (totalSize > maxSize) return 0;
    
    size_t pos = 0;
    
    // Start code
    output[pos++] = 0x00;
    output[pos++] = 0x00;
    output[pos++] = 0x00;
    output[pos++] = 0x01;
    
    // NAL header
    if (isH265) {
        output[pos++] = 0x4E;  // (39 << 1) = 78 = 0x4E, PREFIX_SEI_NUT
        output[pos++] = 0x01;  // nuh_layer_id=0, nuh_temporal_id_plus1=1
    } else {
        output[pos++] = 0x06;  // SEI NAL type for H.264
    }
    
    // Payload type = 5 (user_data_unregistered)
    output[pos++] = 0x05;
    
    // Payload size (RBSP bytes excluding trailing, in escaped form)
    // Note: SEI payloadSize is for unescaped RBSP content, but we write escaped
    // Actually for SEI, payloadSize counts the bytes AFTER escaping in RBSP
    // Wait no - payloadSize is RBSP payload which gets escaped during NAL writing
    // Let's use the raw payload size (before escaping) as per H.264/H.265 spec
    size_t seiPayloadSize = 16 + 4 + 1 + 4;  // UUID + seq + magic + checksum (raw, no trailing)
    if (seiPayloadSize > 127) {
        output[pos++] = 0xFF;
        output[pos++] = static_cast<uint8_t>(seiPayloadSize - 127);
    } else {
        output[pos++] = static_cast<uint8_t>(seiPayloadSize);
    }
    
    // Write payload with emulation prevention
    size_t written = WriteWithEmulationPrevention(rawPayload, rawPos, output + pos, maxSize - pos);
    if (written == 0) return 0;
    
    return pos + written;
}

// Parse SEI NAL to extract our trailer info
bool PassthroughCryptor::ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info) {
    if (size < 30) return false;  // Minimum SEI size
    
    size_t pos = 0;
    
    // Skip start code
    if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) {
        pos = 4;
    } else if (data[0] == 0 && data[1] == 0 && data[2] == 1) {
        pos = 3;
    } else {
        return false;
    }
    
    // Check NAL type (SEI = 6 for H.264, 39/40 for H.265)
    if ((data[pos] & 0x80) != 0) return false;
    
    uint8_t h264Type = data[pos] & 0x1F;
    uint8_t h265Type = (data[pos] >> 1) & 0x3F;
    if (h264Type == 6) {
        pos += 1;
    } else if (h265Type == 39 || h265Type == 40) {
        pos += 2;
    } else {
        return false;
    }
    
    // Check payload type (should be 5 = user_data_unregistered)
    if (pos >= size || data[pos] != 0x05) return false;
    pos++;
    
    // Parse payload size (this is the RBSP size, before escaping)
    size_t payloadSize = 0;
    while (pos < size && data[pos] == 0xFF) {
        payloadSize += 255;
        pos++;
    }
    if (pos >= size) return false;
    payloadSize += data[pos++];
    
    // Check minimum expected size
    if (payloadSize < 16 + 4 + 1 + 4) return false;  // UUID + seq + magic + checksum
    
    // Calculate how much escaped data we have (may be larger than payloadSize)
    size_t remainingData = size - pos;
    if (remainingData < payloadSize) return false;  // Not enough data
    
    // De-escape the payload (remove emulation prevention bytes)
    uint8_t deescaped[64];
    size_t deescapedSize = ReadWithEmulationPreventionRemoval(
        data + pos, remainingData, deescaped, sizeof(deescaped));
    
    if (deescapedSize < payloadSize) return false;
    
    size_t p = 0;
    
    // Check UUID
    if (memcmp(deescaped + p, kSeiUuid, 16) != 0) return false;
    p += 16;
    
    // Read sequence number
    info.seqNum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                  (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                  (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                  static_cast<uint32_t>(deescaped[p + 3]);
    p += 4;
    
    // Read magic byte
    info.magic = deescaped[p++];
    if (info.magic != kVideoMagic) return false;
    
    // Read checksum
    info.checksum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                    (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                    (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                    static_cast<uint32_t>(deescaped[p + 3]);
    
    return true;
}

CryptResult PassthroughCryptor::EncryptVideo(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    bool isH265 = DetectH265(plaintext, plaintextSize);
    auto nalUnits = FindNalUnits(plaintext, plaintextSize, isH265);
    
    if (nalUnits.empty()) {
        return EncryptAudio(plaintext, plaintextSize, ciphertext, ciphertextMaxSize);
    }
    
    // SEI-based approach: insert SEI NAL before each encrypted NAL
    // NAL content is NOT modified (passthrough), SEI carries checksum
    
    size_t outPos = 0;
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : plaintextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        if (nal.should_encrypt) {
            // Compute checksum of NAL content
            uint32_t checksum = ComputeChecksum(plaintext + nal.start_offset + nal.header_size, nalContentSize);
            
            // Write SEI NAL with our trailer info
            size_t seiSize = WriteSeiNal(ciphertext + outPos, ciphertextMaxSize - outPos, 
                                          _seqNum++, checksum, isH265);
            if (seiSize == 0) return CryptResult::Failed();
            outPos += seiSize;
            
            // Copy original NAL unchanged (passthrough!)
            if (outPos + nalTotalSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        } else {
            // Copy non-encrypted NAL as-is
            if (outPos + nalTotalSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    return CryptResult::Ok(outPos);
}

size_t PassthroughCryptor::GetMaxAudioCiphertextSize(size_t plaintextSize) const {
    return plaintextSize + 1 + kChecksumSize + 64;
}

size_t PassthroughCryptor::GetMaxVideoCiphertextSize(size_t plaintextSize) const {
    // SEI-based: original data + SEI NAL per encrypted NAL (max ~40 bytes each)
    // Assume up to 32 NAL units
    return plaintextSize + 32 * 50;
}

int PassthroughCryptor::TryFindAudioKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    size_t trailerSize = 1 + kChecksumSize;
    if (ciphertextSize < trailerSize) return -1;
    
    size_t trailerPos = ciphertextSize - trailerSize;
    if (ciphertext[trailerPos] != kAudioMagic) return -1;
    
    // Passthrough accepts any key (or no key)
    return 0;
}

int PassthroughCryptor::TryFindVideoKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    // Look for our SEI NAL to confirm this is our encrypted data
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    for (const auto& nal : nalUnits) {
        // Check if this is an SEI NAL (type 6 for H.264, 39/40 for H.265)
        size_t headerPos = nal.start_offset + (nal.header_size > 4 ? 4 : 3);
        if (headerPos >= ciphertextSize) continue;
        
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = false;
        if (isH265) {
            uint8_t nalType = (nalByte >> 1) & 0x3F;
            isSei = (nalType == 39 || nalType == 40);
        } else {
            uint8_t nalType = nalByte & 0x1F;
            isSei = (nalType == 6);
        }
        
        if (isSei) {
            PendingSeiInfo info;
            size_t nalEnd = ciphertextSize;
            for (size_t j = 0; j < nalUnits.size(); j++) {
                if (&nalUnits[j] == &nal && j + 1 < nalUnits.size()) {
                    nalEnd = nalUnits[j + 1].start_offset;
                    break;
                }
            }
            if (ParseSeiNal(ciphertext + nal.start_offset, nalEnd - nal.start_offset, info)) {
                return 0;  // Found our SEI, passthrough accepts any key
            }
        }
    }
    return -1;  // No SEI found
}

CryptResult PassthroughCryptor::DecryptAudio(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    // Format: [MAGIC 1B][DATA][CHECKSUM 4B]
    size_t overheadSize = 1 + kChecksumSize;
    if (ciphertextSize < overheadSize) return CryptResult::Failed();
    
    size_t payloadSize = ciphertextSize - overheadSize;
    if (payloadSize > plaintextMaxSize) return CryptResult::Failed();
    
    // Copy payload (skip magic byte at start)
    memcpy(plaintext, ciphertext + 1, payloadSize);
    
    // Verify checksum
    size_t checksumPos = ciphertextSize - kChecksumSize;
    uint32_t storedChecksum = (static_cast<uint32_t>(ciphertext[checksumPos]) << 24) |
                              (static_cast<uint32_t>(ciphertext[checksumPos + 1]) << 16) |
                              (static_cast<uint32_t>(ciphertext[checksumPos + 2]) << 8) |
                              static_cast<uint32_t>(ciphertext[checksumPos + 3]);
    
    uint32_t computedChecksum = ComputeChecksum(plaintext, payloadSize);
    if (storedChecksum != computedChecksum) {
        return CryptResult::Failed();
    }
    
    return CryptResult::Ok(payloadSize);
}

CryptResult PassthroughCryptor::DecryptVideo(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    if (nalUnits.empty()) {
        return DecryptAudio(ciphertext, ciphertextSize, plaintext, plaintextMaxSize);
    }
    
    // SEI-based decryption:
    // 1. Find SEI NALs with our UUID and extract trailer info
    // 2. For VCL NALs following SEI, verify checksum
    // 3. Skip SEI NALs in output, copy VCL NALs unchanged
    
    size_t outPos = 0;
    PendingSeiInfo currentSei;
    bool havePendingSei = false;
    
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        // Check if this is an SEI NAL
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = false;
        if (isH265) {
            uint8_t nalType = (nalByte >> 1) & 0x3F;
            isSei = (nalType == 39 || nalType == 40);
        } else {
            uint8_t nalType = nalByte & 0x1F;
            isSei = (nalType == 6);
        }
        
        if (isSei) {
            // Try to parse as our SEI
            if (ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, currentSei)) {
                havePendingSei = true;
                // Store in pending map for out-of-order packets
                _pendingSeis[currentSei.seqNum] = currentSei;
            } else {
                // Not our SEI, copy it to output
                if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
                memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
                outPos += nalTotalSize;
            }
            continue;  // Don't output our SEI NALs
        }
        
        if (nal.should_encrypt && havePendingSei) {
            // Verify checksum
            uint32_t computed = ComputeChecksum(ciphertext + nal.start_offset + nal.header_size, nalContentSize);
            if (computed != currentSei.checksum) {
                LOGW("Passthrough: checksum mismatch, expected %08x got %08x", currentSei.checksum, computed);
            }
            havePendingSei = false;
        }
        
        // Copy NAL to output (unchanged for passthrough)
        if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
        memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
        outPos += nalTotalSize;
    }
    
    // Clean up old pending SEIs (keep only last 100)
    while (_pendingSeis.size() > 100) {
        _pendingSeis.erase(_pendingSeis.begin());
    }
    
    return CryptResult::Ok(outPos);
}

// ==================== BLOCK XOR (Debug) ====================

BlockXorCryptor::BlockXorCryptor() {}
BlockXorCryptor::~BlockXorCryptor() {}

void BlockXorCryptor::SetKey(const std::vector<uint8_t>& key) {
    _key = key;
    // Ensure key is at least 32 bytes (pad with zeros if needed)
    while (_key.size() < 32) {
        _key.push_back(0);
    }
}

void BlockXorCryptor::XorData(const uint8_t* input, uint8_t* output, size_t size) {
    for (size_t i = 0; i < size; i++) {
        output[i] = input[i] ^ _key[i % _key.size()];
    }
}

uint32_t BlockXorCryptor::ComputeChecksum(const uint8_t* data, size_t size) {
    // CRC32-like checksum using key
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
        }
    }
    // Mix in key
    for (size_t i = 0; i < _key.size() && i < 4; i++) {
        crc ^= (static_cast<uint32_t>(_key[i]) << (i * 8));
    }
    return crc ^ 0xFFFFFFFF;
}

CryptResult BlockXorCryptor::EncryptAudio(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    // Format: [MAGIC 1B][XOR_DATA][CHECKSUM 4B]
    size_t totalSize = 1 + plaintextSize + kChecksumSize;
    
    if (totalSize > ciphertextMaxSize) return CryptResult::Failed();
    
    // Magic byte first
    ciphertext[0] = kAudioMagic;
    
    // XOR encrypt (skip magic byte)
    XorData(plaintext, ciphertext + 1, plaintextSize);
    
    // Checksum of ORIGINAL data (before XOR)
    uint32_t checksum = ComputeChecksum(plaintext, plaintextSize);
    size_t pos = 1 + plaintextSize;
    ciphertext[pos++] = (checksum >> 24) & 0xFF;
    ciphertext[pos++] = (checksum >> 16) & 0xFF;
    ciphertext[pos++] = (checksum >> 8) & 0xFF;
    ciphertext[pos++] = checksum & 0xFF;
    
    return CryptResult::Ok(totalSize);
}

// Write SEI NAL with our custom trailer for XOR
size_t BlockXorCryptor::WriteSeiNal(uint8_t* output, size_t maxSize, 
                                     uint32_t seqNum, uint32_t checksum, bool isH265) {
    // Build raw payload with emulation prevention
    uint8_t rawPayload[32];
    size_t rawPos = 0;
    
    memcpy(rawPayload + rawPos, kSeiUuid, 16);
    rawPos += 16;
    
    rawPayload[rawPos++] = (seqNum >> 24) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 16) & 0xFF;
    rawPayload[rawPos++] = (seqNum >> 8) & 0xFF;
    rawPayload[rawPos++] = seqNum & 0xFF;
    
    rawPayload[rawPos++] = kVideoMagic;
    
    rawPayload[rawPos++] = (checksum >> 24) & 0xFF;
    rawPayload[rawPos++] = (checksum >> 16) & 0xFF;
    rawPayload[rawPos++] = (checksum >> 8) & 0xFF;
    rawPayload[rawPos++] = checksum & 0xFF;
    
    rawPayload[rawPos++] = 0x80;  // RBSP trailing
    
    size_t escapedPayloadSize = CalculateEscapedSize(rawPayload, rawPos);
    size_t seiPayloadSize = 16 + 4 + 1 + 4;  // Raw payload size (for SEI header)
    size_t headerSize = 4 + (isH265 ? 2 : 1) + 1 + (seiPayloadSize > 127 ? 2 : 1);
    size_t totalSize = headerSize + escapedPayloadSize;
    
    if (totalSize > maxSize) return 0;
    
    size_t pos = 0;
    
    // Start code
    output[pos++] = 0x00;
    output[pos++] = 0x00;
    output[pos++] = 0x00;
    output[pos++] = 0x01;
    
    // NAL header
    if (isH265) {
        output[pos++] = 0x4E;  // PREFIX_SEI_NUT
        output[pos++] = 0x01;
    } else {
        output[pos++] = 0x06;  // SEI
    }
    
    // Payload type = 5
    output[pos++] = 0x05;
    
    // Payload size
    if (seiPayloadSize > 127) {
        output[pos++] = 0xFF;
        output[pos++] = static_cast<uint8_t>(seiPayloadSize - 127);
    } else {
        output[pos++] = static_cast<uint8_t>(seiPayloadSize);
    }
    
    // Write escaped payload
    size_t written = WriteWithEmulationPrevention(rawPayload, rawPos, output + pos, maxSize - pos);
    if (written == 0) return 0;
    
    return pos + written;
}

bool BlockXorCryptor::ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info) {
    if (size < 30) return false;
    
    size_t pos = 0;
    if (data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 1) pos = 4;
    else if (data[0] == 0 && data[1] == 0 && data[2] == 1) pos = 3;
    else return false;
    
    uint8_t nalByte = data[pos];
    if ((nalByte & 0x80) != 0) return false;
    
    uint8_t h264Type = nalByte & 0x1F;
    uint8_t h265Type = (nalByte >> 1) & 0x3F;
    if (h264Type == 6) pos += 1;
    else if (h265Type == 39 || h265Type == 40) pos += 2;
    else return false;
    
    if (pos >= size || data[pos] != 0x05) return false;
    pos++;
    
    size_t payloadSize = 0;
    while (pos < size && data[pos] == 0xFF) { payloadSize += 255; pos++; }
    if (pos >= size) return false;
    payloadSize += data[pos++];
    
    if (payloadSize < 25) return false;
    
    size_t remainingData = size - pos;
    if (remainingData < payloadSize) return false;
    
    // De-escape the payload
    uint8_t deescaped[64];
    size_t deescapedSize = ReadWithEmulationPreventionRemoval(
        data + pos, remainingData, deescaped, sizeof(deescaped));
    
    if (deescapedSize < payloadSize) return false;
    
    size_t p = 0;
    if (memcmp(deescaped + p, kSeiUuid, 16) != 0) return false;
    p += 16;
    
    info.seqNum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                  (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                  (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                  static_cast<uint32_t>(deescaped[p + 3]);
    p += 4;
    
    info.magic = deescaped[p++];
    if (info.magic != kVideoMagic) return false;
    
    info.checksum = (static_cast<uint32_t>(deescaped[p]) << 24) |
                    (static_cast<uint32_t>(deescaped[p + 1]) << 16) |
                    (static_cast<uint32_t>(deescaped[p + 2]) << 8) |
                    static_cast<uint32_t>(deescaped[p + 3]);
    
    return true;
}

CryptResult BlockXorCryptor::EncryptVideo(
    const uint8_t* plaintext, size_t plaintextSize,
    uint8_t* ciphertext, size_t ciphertextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    bool isH265 = DetectH265(plaintext, plaintextSize);
    auto nalUnits = FindNalUnits(plaintext, plaintextSize, isH265);
    
    if (nalUnits.empty()) {
        return EncryptAudio(plaintext, plaintextSize, ciphertext, ciphertextMaxSize);
    }
    
    // SEI-based: insert SEI NAL before each encrypted NAL
    // XOR encrypt NAL payload, then escape to prevent false start codes
    
    size_t outPos = 0;
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : plaintextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        if (nal.should_encrypt && nalContentSize > 0) {
            const uint8_t* payload = plaintext + nal.start_offset + nal.header_size;
            
            // Compute checksum of ORIGINAL payload
            uint32_t checksum = ComputeChecksum(payload, nalContentSize);
            
            // XOR encrypt to temp buffer
            std::vector<uint8_t> xorPayload(nalContentSize);
            XorData(payload, xorPayload.data(), nalContentSize);
            
            // Calculate escaped size
            size_t escapedSize = CalculateEscapedSize(xorPayload.data(), nalContentSize);
            
            // Write SEI NAL (include original payload size for decoding)
            size_t seiSize = WriteSeiNal(ciphertext + outPos, ciphertextMaxSize - outPos,
                                          _seqNum++, checksum, isH265);
            if (seiSize == 0) return CryptResult::Failed();
            outPos += seiSize;
            
            // Copy NAL header
            if (outPos + nal.header_size + escapedSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            // Write escaped XOR'd payload
            size_t written = WriteWithEmulationPrevention(xorPayload.data(), nalContentSize, 
                                                           ciphertext + outPos, ciphertextMaxSize - outPos);
            if (written == 0) return CryptResult::Failed();
            outPos += written;
        } else {
            // Copy non-encrypted NAL as-is
            if (outPos + nalTotalSize > ciphertextMaxSize) return CryptResult::Failed();
            memcpy(ciphertext + outPos, plaintext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    return CryptResult::Ok(outPos);
}

size_t BlockXorCryptor::GetMaxAudioCiphertextSize(size_t plaintextSize) const {
    return plaintextSize + 1 + kChecksumSize + 64;
}

size_t BlockXorCryptor::GetMaxVideoCiphertextSize(size_t plaintextSize) const {
    // SEI-based: original data + SEI NAL per encrypted NAL + emulation prevention (worst case ~1.5x)
    return (plaintextSize * 2) + 32 * 50;
}

int BlockXorCryptor::TryFindAudioKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    size_t trailerSize = 1 + kChecksumSize;
    if (ciphertextSize < trailerSize) return -1;
    
    size_t trailerPos = ciphertextSize - trailerSize;
    if (ciphertext[trailerPos] != kAudioMagic) return -1;
    
    size_t payloadSize = ciphertextSize - trailerSize;
    
    // Read stored checksum
    size_t checksumPos = ciphertextSize - kChecksumSize;
    uint32_t storedChecksum = (static_cast<uint32_t>(ciphertext[checksumPos]) << 24) |
                              (static_cast<uint32_t>(ciphertext[checksumPos + 1]) << 16) |
                              (static_cast<uint32_t>(ciphertext[checksumPos + 2]) << 8) |
                              static_cast<uint32_t>(ciphertext[checksumPos + 3]);
    
    // Try each key
    std::vector<uint8_t> decrypted(payloadSize);
    for (size_t k = 0; k < keys.size(); k++) {
        _key = keys[k];
        while (_key.size() < 32) _key.push_back(0);
        
        XorData(ciphertext, decrypted.data(), payloadSize);
        uint32_t computed = ComputeChecksum(decrypted.data(), payloadSize);
        
        if (computed == storedChecksum) {
            return static_cast<int>(k);
        }
    }
    
    return -1;
}

int BlockXorCryptor::TryFindVideoKey(
    const std::vector<std::vector<uint8_t>>& keys,
    const uint8_t* ciphertext, size_t ciphertextSize) {
    
    // Find SEI with our UUID, then try to verify checksum with each key
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    PendingSeiInfo seiInfo;
    size_t encryptedNalIdx = SIZE_MAX;
    
    // Find our SEI and the following encrypted NAL
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = false;
        if (isH265) {
            isSei = (((nalByte >> 1) & 0x3F) == 39 || ((nalByte >> 1) & 0x3F) == 40);
        } else {
            isSei = ((nalByte & 0x1F) == 6);
        }
        
        if (isSei && ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, seiInfo)) {
            // Found our SEI, next encrypted NAL is the one to verify
            for (size_t j = i + 1; j < nalUnits.size(); j++) {
                if (nalUnits[j].should_encrypt) {
                    encryptedNalIdx = j;
                    break;
                }
            }
            break;
        }
    }
    
    if (encryptedNalIdx == SIZE_MAX) return -1;
    
    const auto& nal = nalUnits[encryptedNalIdx];
    size_t nalEnd = (encryptedNalIdx + 1 < nalUnits.size()) ? 
                    nalUnits[encryptedNalIdx + 1].start_offset : ciphertextSize;
    size_t nalContentSize = nalEnd - nal.start_offset - nal.header_size;
    
    // First unescape the encrypted payload (remove emulation prevention bytes)
    std::vector<uint8_t> unescaped(nalContentSize);
    size_t unescapedSize = ReadWithEmulationPreventionRemoval(
        ciphertext + nal.start_offset + nal.header_size, nalContentSize,
        unescaped.data(), unescaped.size());
    
    // Try each key
    std::vector<uint8_t> decrypted(unescapedSize);
    for (size_t k = 0; k < keys.size(); k++) {
        _key = keys[k];
        while (_key.size() < 32) _key.push_back(0);
        
        XorData(unescaped.data(), decrypted.data(), unescapedSize);
        uint32_t computed = ComputeChecksum(decrypted.data(), unescapedSize);
        
        if (computed == seiInfo.checksum) {
            return static_cast<int>(k);
        }
    }
    
    return -1;
}

CryptResult BlockXorCryptor::DecryptAudio(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    // Format: [MAGIC 1B][XOR_DATA][CHECKSUM 4B]
    size_t overheadSize = 1 + kChecksumSize;
    if (ciphertextSize < overheadSize) return CryptResult::Failed();
    
    size_t payloadSize = ciphertextSize - overheadSize;
    if (payloadSize > plaintextMaxSize) return CryptResult::Failed();
    
    // XOR decrypt (skip magic byte)
    XorData(ciphertext + 1, plaintext, payloadSize);
    
    // Verify checksum
    size_t checksumPos = ciphertextSize - kChecksumSize;
    uint32_t storedChecksum = (static_cast<uint32_t>(ciphertext[checksumPos]) << 24) |
                              (static_cast<uint32_t>(ciphertext[checksumPos + 1]) << 16) |
                              (static_cast<uint32_t>(ciphertext[checksumPos + 2]) << 8) |
                              static_cast<uint32_t>(ciphertext[checksumPos + 3]);
    
    uint32_t computedChecksum = ComputeChecksum(plaintext, payloadSize);
    if (storedChecksum != computedChecksum) {
        return CryptResult::Failed();
    }
    
    return CryptResult::Ok(payloadSize);
}

CryptResult BlockXorCryptor::DecryptVideo(
    const uint8_t* ciphertext, size_t ciphertextSize,
    uint8_t* plaintext, size_t plaintextMaxSize) {
    
    if (_key.empty()) return CryptResult::Failed();
    
    bool isH265 = DetectH265(ciphertext, ciphertextSize);
    auto nalUnits = FindNalUnits(ciphertext, ciphertextSize, isH265);
    
    if (nalUnits.empty()) {
        return DecryptAudio(ciphertext, ciphertextSize, plaintext, plaintextMaxSize);
    }
    
    // SEI-based decryption
    size_t outPos = 0;
    PendingSeiInfo currentSei;
    bool havePendingSei = false;
    
    for (size_t i = 0; i < nalUnits.size(); i++) {
        const auto& nal = nalUnits[i];
        size_t nalEnd = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : ciphertextSize;
        size_t nalTotalSize = nalEnd - nal.start_offset;
        size_t nalContentSize = nalTotalSize - nal.header_size;
        
        // Check if this is an SEI NAL
        size_t headerPos = nal.start_offset + (nal.header_size > 5 ? 4 : 3);
        uint8_t nalByte = ciphertext[headerPos];
        bool isSei = false;
        if (isH265) {
            uint8_t nalType = (nalByte >> 1) & 0x3F;
            isSei = (nalType == 39 || nalType == 40);
        } else {
            uint8_t nalType = nalByte & 0x1F;
            isSei = (nalType == 6);
        }
        
        if (isSei) {
            if (ParseSeiNal(ciphertext + nal.start_offset, nalTotalSize, currentSei)) {
                havePendingSei = true;
                _pendingSeis[currentSei.seqNum] = currentSei;
            } else {
                // Not our SEI, copy it
                if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
                memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
                outPos += nalTotalSize;
            }
            continue;
        }
        
        if (nal.should_encrypt && havePendingSei && nalContentSize > 0) {
            // Copy NAL header
            if (outPos + nal.header_size > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nal.header_size);
            outPos += nal.header_size;
            
            // First remove emulation prevention bytes from encrypted payload
            std::vector<uint8_t> unescaped(nalContentSize);
            size_t unescapedSize = ReadWithEmulationPreventionRemoval(
                ciphertext + nal.start_offset + nal.header_size, nalContentSize,
                unescaped.data(), unescaped.size());
            
            // XOR decrypt the unescaped payload
            if (outPos + unescapedSize > plaintextMaxSize) return CryptResult::Failed();
            XorData(unescaped.data(), plaintext + outPos, unescapedSize);
            outPos += unescapedSize;
            
            havePendingSei = false;
        } else {
            // Copy NAL unchanged
            if (outPos + nalTotalSize > plaintextMaxSize) return CryptResult::Failed();
            memcpy(plaintext + outPos, ciphertext + nal.start_offset, nalTotalSize);
            outPos += nalTotalSize;
        }
    }
    
    while (_pendingSeis.size() > 100) {
        _pendingSeis.erase(_pendingSeis.begin());
    }
    
    return CryptResult::Ok(outPos);
}

// ==================== Factory ====================

std::unique_ptr<IFrameEncryptor> CryptorFactory::CreateEncryptor(int type) {
    switch (type) {
        case 0: return std::make_unique<Aes256Cryptor>();
        case 1: return std::make_unique<Gost28147Cryptor>();
        case 2: return std::make_unique<Aes256LiteCryptor>();
        case 3: return std::make_unique<GostLiteCryptor>();
        case 4: return std::make_unique<PassthroughCryptor>();
        case 5: return std::make_unique<BlockXorCryptor>();
        default: return nullptr;
    }
}

std::unique_ptr<IFrameDecryptor> CryptorFactory::CreateDecryptorByAudioMagic(uint8_t magicByte) {
    if (magicByte == Aes256Cryptor::kAudioMagic) return std::make_unique<Aes256Cryptor>();
    if (magicByte == Gost28147Cryptor::kAudioMagic) return std::make_unique<Gost28147Cryptor>();
    if (magicByte == Aes256LiteCryptor::kAudioMagic) return std::make_unique<Aes256LiteCryptor>();
    if (magicByte == GostLiteCryptor::kAudioMagic) return std::make_unique<GostLiteCryptor>();
    if (magicByte == PassthroughCryptor::kAudioMagic) return std::make_unique<PassthroughCryptor>();
    if (magicByte == BlockXorCryptor::kAudioMagic) return std::make_unique<BlockXorCryptor>();
    return nullptr;
}

std::unique_ptr<IFrameDecryptor> CryptorFactory::CreateDecryptorByVideoMagic(uint8_t magicByte) {
    if (magicByte == Aes256Cryptor::kVideoMagic) return std::make_unique<Aes256Cryptor>();
    if (magicByte == Gost28147Cryptor::kVideoMagic) return std::make_unique<Gost28147Cryptor>();
    if (magicByte == Aes256LiteCryptor::kVideoMagic) return std::make_unique<Aes256LiteCryptor>();
    if (magicByte == GostLiteCryptor::kVideoMagic) return std::make_unique<GostLiteCryptor>();
    if (magicByte == PassthroughCryptor::kVideoMagic) return std::make_unique<PassthroughCryptor>();
    if (magicByte == BlockXorCryptor::kVideoMagic) return std::make_unique<BlockXorCryptor>();
    return nullptr;
}

bool CryptorFactory::IsKnownAudioMagic(uint8_t magic) {
    return magic == Aes256Cryptor::kAudioMagic ||
           magic == Gost28147Cryptor::kAudioMagic ||
           magic == Aes256LiteCryptor::kAudioMagic ||
           magic == GostLiteCryptor::kAudioMagic ||
           magic == PassthroughCryptor::kAudioMagic ||
           magic == BlockXorCryptor::kAudioMagic;
}

bool CryptorFactory::IsKnownVideoMagic(uint8_t magic) {
    return magic == Aes256Cryptor::kVideoMagic ||
           magic == Gost28147Cryptor::kVideoMagic ||
           magic == Aes256LiteCryptor::kVideoMagic ||
           magic == GostLiteCryptor::kVideoMagic ||
           magic == PassthroughCryptor::kVideoMagic ||
           magic == BlockXorCryptor::kVideoMagic;
}

} // namespace tgcalls
