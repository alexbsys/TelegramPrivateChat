#include "CustomFrameEncryptorImpl.h"
#include "CustomEncryptionManager.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <android/log.h>
#include <cstring>
#include <vector>

#define LOG_TAG "CustomFrameEncryptor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace tgcalls {

// ==================== NAL Unit Parsing Helpers ====================

// NAL unit info: start offset, header size, and whether it should be encrypted
struct NalUnitInfo {
    size_t start_offset;
    size_t header_size;
    bool should_encrypt;  // false for SPS/PPS/VPS
};

// Check if NAL unit type should be encrypted
// Returns false for parameter sets (SPS, PPS, VPS) which decoder needs to read
static bool ShouldEncryptNalType(uint8_t nal_type, bool isH265) {
    if (isH265) {
        // H.265 NAL unit types:
        // 0-31: VCL NAL units (video data) - ENCRYPT
        // 32: VPS - DON'T ENCRYPT
        // 33: SPS - DON'T ENCRYPT
        // 34: PPS - DON'T ENCRYPT
        // 35-40: AUD, SEI, etc. - DON'T ENCRYPT (small, non-sensitive)
        return (nal_type <= 31);
    } else {
        // H.264 NAL unit types:
        // 1: Non-IDR slice - ENCRYPT
        // 2-4: Data partitions - ENCRYPT
        // 5: IDR slice - ENCRYPT
        // 6: SEI - DON'T ENCRYPT (non-sensitive metadata)
        // 7: SPS - DON'T ENCRYPT (decoder needs this)
        // 8: PPS - DON'T ENCRYPT (decoder needs this)
        // 9-12: AUD, end of sequence, etc. - DON'T ENCRYPT
        return (nal_type >= 1 && nal_type <= 5);
    }
}

// Find all NAL unit boundaries in H.264/H.265 bitstream
// Returns vector of NalUnitInfo with start offset, header size, and encryption flag
static std::vector<NalUnitInfo> FindNalUnits(const uint8_t* data, size_t size, bool isH265) {
    std::vector<NalUnitInfo> units;
    
    size_t i = 0;
    while (i + 3 < size) {
        // Look for start code: 00 00 01 or 00 00 00 01
        if (data[i] == 0 && data[i+1] == 0) {
            size_t start_code_len = 0;
            if (data[i+2] == 1) {
                start_code_len = 3;
            } else if (i + 4 <= size && data[i+2] == 0 && data[i+3] == 1) {
                start_code_len = 4;
            }
            
            if (start_code_len > 0) {
                // NAL header: 1 byte for H.264, 2 bytes for H.265
                size_t nal_header_len = isH265 ? 2 : 1;
                size_t total_header = start_code_len + nal_header_len;
                
                if (i + total_header <= size) {
                    // Extract NAL type
                    uint8_t nal_header_byte = data[i + start_code_len];
                    uint8_t nal_type;
                    if (isH265) {
                        // H.265: nal_unit_type is bits 1-6 of first byte
                        nal_type = (nal_header_byte >> 1) & 0x3F;
                    } else {
                        // H.264: nal_unit_type is bits 0-4 of first byte
                        nal_type = nal_header_byte & 0x1F;
                    }
                    
                    bool should_encrypt = ShouldEncryptNalType(nal_type, isH265);
                    units.push_back({i, total_header, should_encrypt});
                }
                i += start_code_len;
                continue;
            }
        }
        i++;
    }
    
    return units;
}

// Detect if frame is H.265 based on NAL unit type
static bool DetectH265(const uint8_t* data, size_t size) {
    // Find first NAL unit
    size_t i = 0;
    while (i + 4 < size) {
        if (data[i] == 0 && data[i+1] == 0) {
            size_t start_code_len = 0;
            if (data[i+2] == 1) {
                start_code_len = 3;
            } else if (data[i+2] == 0 && data[i+3] == 1) {
                start_code_len = 4;
            }
            
            if (start_code_len > 0 && i + start_code_len < size) {
                // Check NAL header
                // H.264: forbidden_bit(1) + nal_ref_idc(2) + nal_unit_type(5)
                // H.265: forbidden_bit(1) + nal_unit_type(6) + nuh_layer_id(6) + nuh_temporal_id_plus1(3)
                uint8_t first_byte = data[i + start_code_len];
                
                // In H.265, NAL unit types 0-31 are VCL NALs, 32-63 are non-VCL
                // H.264 NAL types are 0-31
                // If we see type > 31 in the standard position, it could be H.265
                // But better heuristic: H.265 has two-byte header, check if format makes sense
                
                // For now, check based on frame structure patterns
                // H.265 VPS/SPS/PPS have specific NAL types: 32, 33, 34
                uint8_t nal_type_h265 = (first_byte >> 1) & 0x3F;
                if (nal_type_h265 >= 32 && nal_type_h265 <= 40) {
                    return true; // Looks like H.265 parameter set
                }
                
                // Default to H.264 as it's more common
                return false;
            }
        }
        i++;
    }
    return false;
}

// ==================== CustomFrameEncryptorImpl ====================

CustomFrameEncryptorImpl::CustomFrameEncryptorImpl() {
    LOGI("CustomFrameEncryptorImpl created");
}

int CustomFrameEncryptorImpl::Encrypt(cricket::MediaType media_type,
                                       uint32_t ssrc,
                                       rtc::ArrayView<const uint8_t> additional_data,
                                       rtc::ArrayView<const uint8_t> frame,
                                       rtc::ArrayView<uint8_t> encrypted_frame,
                                       size_t* bytes_written) {
    // Get key from manager dynamically
    auto key = CustomEncryptionManager::getInstance().getOutgoingKey();
    
    // If no key, pass through unencrypted
    if (key.empty()) {
        if (encrypted_frame.size() >= frame.size()) {
            memcpy(encrypted_frame.data(), frame.data(), frame.size());
            *bytes_written = frame.size();
            return 0;
        }
        return 1;
    }
    
    // Normalize key to 32 bytes
    while (key.size() < 32) key.push_back(0);
    if (key.size() > 32) key.resize(32);
    
    _encryptCount++;
    bool isVideo = (media_type == cricket::MediaType::MEDIA_TYPE_VIDEO);
    if (isVideo) {
        _videoEncryptCount++;
    } else {
        _audioEncryptCount++;
    }
    
    if (_encryptCount % 100 == 1 || (isVideo && _videoEncryptCount <= 10)) {
        LOGI("Encrypt: frame_size=%zu, media=%d (video=%d), ssrc=%u, total=%d, audio=%d, video=%d", 
             frame.size(), static_cast<int>(media_type), isVideo ? 1 : 0, ssrc, 
             _encryptCount, _audioEncryptCount, _videoEncryptCount);
    }
    
    // For audio: full frame encryption (as before)
    // For video: selective NAL unit encryption to preserve structure for packetizer
    if (!isVideo) {
        return EncryptAudio(key, frame, encrypted_frame, bytes_written);
    } else {
        return EncryptVideo(key, frame, encrypted_frame, bytes_written);
    }
}

int CustomFrameEncryptorImpl::EncryptAudio(const std::vector<uint8_t>& key,
                                            rtc::ArrayView<const uint8_t> frame,
                                            rtc::ArrayView<uint8_t> encrypted_frame,
                                            size_t* bytes_written) {
    // Format: MAGIC_BYTE | IV (12 bytes) | ENCRYPTED_DATA | TAG (16 bytes)
    size_t output_size = 1 + kIvSize + frame.size() + kTagSize;
    if (encrypted_frame.size() < output_size) {
        LOGE("EncryptAudio: buffer too small: %zu < %zu", encrypted_frame.size(), output_size);
        return 1;
    }
    
    // Generate random IV
    uint8_t iv[kIvSize];
    RAND_bytes(iv, kIvSize);
    
    // Write magic byte
    encrypted_frame[0] = kMagicByte;
    
    // Write IV
    memcpy(encrypted_frame.data() + 1, iv, kIvSize);
    
    // Encrypt and get tag
    uint8_t tag[kTagSize];
    size_t encrypted_len = 0;
    
    if (!AesGcmEncrypt(key.data(), key.size(),
                       frame.data(), frame.size(),
                       iv, kIvSize,
                       encrypted_frame.data() + 1 + kIvSize, &encrypted_len,
                       tag, kTagSize)) {
        LOGE("EncryptAudio: AES-GCM encryption failed");
        return 1;
    }
    
    // Append tag
    memcpy(encrypted_frame.data() + 1 + kIvSize + encrypted_len, tag, kTagSize);
    
    *bytes_written = 1 + kIvSize + encrypted_len + kTagSize;
    return 0;
}

int CustomFrameEncryptorImpl::EncryptVideo(const std::vector<uint8_t>& key,
                                            rtc::ArrayView<const uint8_t> frame,
                                            rtc::ArrayView<uint8_t> encrypted_frame,
                                            size_t* bytes_written) {
    // Selective NAL Unit Encryption:
    // We preserve NAL unit structure (start codes + headers) so packetizer can work
    // Only payloads are encrypted
    //
    // Format:
    // [Original NAL structure with encrypted payloads][Trailer: MAGIC | IV | TAG]
    //
    // Each NAL unit: [Start Code][NAL Header][Encrypted Payload]
    // Trailer at end: [0xE1][IV 12 bytes][TAG 16 bytes] = 29 bytes
    
    const size_t kTrailerSize = 1 + kIvSize + kTagSize; // 29 bytes
    
    // Detect codec type
    bool isH265 = DetectH265(frame.data(), frame.size());
    
    // Find all NAL units
    auto nalUnits = FindNalUnits(frame.data(), frame.size(), isH265);
    
    if (nalUnits.empty()) {
        // No NAL units found - encrypt whole frame like audio
        if (_videoEncryptCount % 100 == 1) {
            LOGW("EncryptVideo: no NAL units found, falling back to full encryption");
        }
        return EncryptAudio(key, frame, encrypted_frame, bytes_written);
    }
    
    // Count how many NALs will be encrypted
    int encryptedNalCount = 0;
    int skippedNalCount = 0;
    for (const auto& nal : nalUnits) {
        if (nal.should_encrypt) encryptedNalCount++;
        else skippedNalCount++;
    }
    
    // Calculate output size (same as input + trailer)
    size_t output_size = frame.size() + kTrailerSize;
    if (encrypted_frame.size() < output_size) {
        LOGE("EncryptVideo: buffer too small: %zu < %zu", encrypted_frame.size(), output_size);
        return 1;
    }
    
    // Generate random IV
    uint8_t iv[kIvSize];
    RAND_bytes(iv, kIvSize);
    
    // First, copy entire frame to output
    memcpy(encrypted_frame.data(), frame.data(), frame.size());
    
    // Now encrypt each NAL unit payload in-place using AES-CTR
    // We use CTR mode for in-place encryption (same size input/output)
    // IMPORTANT: We only encrypt VCL NAL units (actual video data)
    // SPS/PPS/VPS are left unencrypted so decoder can read them!
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOGE("EncryptVideo: failed to create cipher context");
        return 1;
    }
    
    bool success = true;
    uint8_t counter[16] = {0};
    memcpy(counter, iv, kIvSize);
    
    // For each NAL unit, encrypt only the payload (after header), if applicable
    for (size_t i = 0; i < nalUnits.size() && success; i++) {
        // Skip parameter sets (SPS/PPS/VPS) - decoder needs to read them
        if (!nalUnits[i].should_encrypt) {
            continue;
        }
        
        size_t nal_start = nalUnits[i].start_offset;
        size_t header_size = nalUnits[i].header_size;
        
        // Find end of this NAL unit (start of next, or end of frame)
        size_t nal_end = (i + 1 < nalUnits.size()) ? nalUnits[i + 1].start_offset : frame.size();
        
        // Payload starts after header
        size_t payload_start = nal_start + header_size;
        size_t payload_size = nal_end - payload_start;
        
        if (payload_size > 0) {
            // Set counter for this NAL unit (use NAL index to differentiate)
            counter[12] = (i >> 24) & 0xFF;
            counter[13] = (i >> 16) & 0xFF;
            counter[14] = (i >> 8) & 0xFF;
            counter[15] = i & 0xFF;
            
            // Encrypt payload in-place with AES-CTR
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), counter) != 1) {
                success = false;
                break;
            }
            
            int outLen;
            if (EVP_EncryptUpdate(ctx, 
                                  encrypted_frame.data() + payload_start,
                                  &outLen,
                                  frame.data() + payload_start,
                                  payload_size) != 1) {
                success = false;
                break;
            }
        }
    }
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (!success) {
        LOGE("EncryptVideo: AES-CTR encryption failed");
        return 1;
    }
    
    // Now compute GMAC (authentication tag) over the entire encrypted frame
    // We use GCM with empty plaintext to get just the tag
    uint8_t tag[kTagSize];
    if (!ComputeGmac(key.data(), key.size(), 
                     iv, kIvSize,
                     encrypted_frame.data(), frame.size(),
                     tag, kTagSize)) {
        LOGE("EncryptVideo: GMAC computation failed");
        return 1;
    }
    
    // Append trailer: MAGIC | IV | TAG
    size_t trailer_offset = frame.size();
    encrypted_frame[trailer_offset] = kVideoMagicByte;  // Different magic for video
    memcpy(encrypted_frame.data() + trailer_offset + 1, iv, kIvSize);
    memcpy(encrypted_frame.data() + trailer_offset + 1 + kIvSize, tag, kTagSize);
    
    *bytes_written = frame.size() + kTrailerSize;
    
    if (_videoEncryptCount % 100 == 1 || _videoEncryptCount <= 5) {
        LOGI("EncryptVideo success: in=%zu, out=%zu, NALs=%zu (encrypted=%d, skipped=%d), isH265=%d", 
             frame.size(), *bytes_written, nalUnits.size(), encryptedNalCount, skippedNalCount, isH265 ? 1 : 0);
    }
    
    return 0;
}

bool CustomFrameEncryptorImpl::ComputeGmac(const uint8_t* key, size_t key_len,
                                            const uint8_t* iv, size_t iv_len,
                                            const uint8_t* aad, size_t aad_len,
                                            uint8_t* tag, size_t tag_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    bool success = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) break;
        
        // Set AAD (no plaintext, just AAD for GMAC)
        int outLen;
        if (EVP_EncryptUpdate(ctx, nullptr, &outLen, aad, aad_len) != 1) break;
        
        // Finalize (no output)
        uint8_t dummy[16];
        if (EVP_EncryptFinal_ex(ctx, dummy, &outLen) != 1) break;
        
        // Get tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag) != 1) break;
        
        success = true;
    } while (false);
    
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

bool CustomFrameEncryptorImpl::VerifyGmac(const uint8_t* key, size_t key_len,
                                           const uint8_t* iv, size_t iv_len,
                                           const uint8_t* aad, size_t aad_len,
                                           const uint8_t* tag, size_t tag_len) {
    uint8_t computed_tag[16];
    if (!ComputeGmac(key, key_len, iv, iv_len, aad, aad_len, computed_tag, tag_len)) {
        return false;
    }
    return memcmp(computed_tag, tag, tag_len) == 0;
}

size_t CustomFrameEncryptorImpl::GetMaxCiphertextByteSize(cricket::MediaType media_type,
                                                          size_t frame_size) {
    // For audio: MAGIC_BYTE + IV + DATA + TAG
    // For video: DATA + MAGIC_BYTE + IV + TAG (trailer)
    return frame_size + 1 + kIvSize + kTagSize;
}

bool CustomFrameEncryptorImpl::AesGcmEncrypt(const uint8_t* key, size_t key_len,
                                              const uint8_t* data, size_t len,
                                              const uint8_t* iv, size_t iv_len,
                                              uint8_t* out, size_t* out_len,
                                              uint8_t* tag, size_t tag_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    bool success = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) break;
        
        int outLen;
        if (EVP_EncryptUpdate(ctx, out, &outLen, data, len) != 1) break;
        
        int finalLen;
        if (EVP_EncryptFinal_ex(ctx, out + outLen, &finalLen) != 1) break;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag) != 1) break;
        
        *out_len = outLen + finalLen;
        success = true;
    } while (false);
    
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

// ==================== CustomFrameDecryptorImpl ====================

CustomFrameDecryptorImpl::CustomFrameDecryptorImpl() {
    LOGI("CustomFrameDecryptorImpl created");
}

webrtc::FrameDecryptorInterface::Result CustomFrameDecryptorImpl::Decrypt(
    cricket::MediaType media_type,
    const std::vector<uint32_t>& csrcs,
    rtc::ArrayView<const uint8_t> additional_data,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {
    
    _decryptCount++;
    bool isVideo = (media_type == cricket::MediaType::MEDIA_TYPE_VIDEO);
    if (isVideo) {
        _videoDecryptCount++;
    } else {
        _audioDecryptCount++;
    }
    
    bool shouldLog = (_decryptCount <= 20) || (_decryptCount % 100 == 0) || 
                     (isVideo && _videoDecryptCount <= 10);
    
    if (shouldLog) {
        uint8_t lastByte = encrypted_frame.size() > 0 ? encrypted_frame[encrypted_frame.size() - 1] : 0;
        // Check for video trailer (magic byte at position size - 29)
        uint8_t trailerMagic = 0;
        if (encrypted_frame.size() >= 29) {
            trailerMagic = encrypted_frame[encrypted_frame.size() - 29];
        }
        LOGI("Decrypt called: size=%zu, media=%d (video=%d), first=0x%02X, last=0x%02X, trailer=0x%02X, count=%d",
             encrypted_frame.size(), static_cast<int>(media_type), isVideo ? 1 : 0,
             encrypted_frame.empty() ? 0 : encrypted_frame[0], lastByte, trailerMagic, _decryptCount);
    }
    
    // Get keys from manager dynamically
    auto keys = CustomEncryptionManager::getInstance().getIncomingKeys();
    
    // Check for video encryption (trailer with kVideoMagicByte)
    const size_t kTrailerSize = 1 + kIvSize + kTagSize; // 29 bytes
    bool isVideoEncrypted = false;
    if (encrypted_frame.size() >= kTrailerSize) {
        size_t trailerOffset = encrypted_frame.size() - kTrailerSize;
        if (encrypted_frame[trailerOffset] == kVideoMagicByte) {
            isVideoEncrypted = true;
        }
    }
    
    // Check for audio encryption (starts with kMagicByte)
    bool isAudioEncrypted = !encrypted_frame.empty() && encrypted_frame[0] == kMagicByte;
    
    if (!isAudioEncrypted && !isVideoEncrypted) {
        // Not encrypted - pass through
        if (shouldLog) {
            LOGI("Decrypt: NOT encrypted, size=%zu, media=%d, count=%d", 
                 encrypted_frame.size(), static_cast<int>(media_type), _decryptCount);
        }
        if (frame.size() >= encrypted_frame.size()) {
            memcpy(frame.data(), encrypted_frame.data(), encrypted_frame.size());
            CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::Disabled);
            return Result(Status::kOk, encrypted_frame.size());
        }
        LOGE("Decrypt: buffer too small: frame_buf=%zu < encrypted=%zu", frame.size(), encrypted_frame.size());
        return Result(Status::kFailedToDecrypt, 0);
    }
    
    if (keys.empty()) {
        LOGW("Decrypt: no keys, encrypted frame size=%zu", encrypted_frame.size());
        CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionFailed);
        return Result(Status::kFailedToDecrypt, 0);
    }
    
    if (shouldLog) {
        LOGI("Decrypt: IS encrypted (audio=%d, video=%d), size=%zu, keys=%zu", 
             isAudioEncrypted ? 1 : 0, isVideoEncrypted ? 1 : 0, 
             encrypted_frame.size(), keys.size());
    }
    
    // Route to appropriate decryption method
    if (isVideoEncrypted) {
        return DecryptVideo(keys, encrypted_frame, frame);
    } else {
        return DecryptAudio(keys, encrypted_frame, frame);
    }
}

webrtc::FrameDecryptorInterface::Result CustomFrameDecryptorImpl::DecryptAudio(
    const std::vector<std::vector<uint8_t>>& keys,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {
    
    // Check minimum size: MAGIC + IV + at least 1 byte + TAG
    if (encrypted_frame.size() < 1 + kIvSize + kTagSize) {
        LOGW("DecryptAudio: frame too small: %zu", encrypted_frame.size());
        return Result(Status::kFailedToDecrypt, 0);
    }
    
    // Extract IV
    const uint8_t* iv = encrypted_frame.data() + 1;
    
    // Encrypted data starts after MAGIC + IV, ends before TAG
    const uint8_t* encrypted_data = encrypted_frame.data() + 1 + kIvSize;
    size_t encrypted_len = encrypted_frame.size() - 1 - kIvSize - kTagSize;
    
    // Tag is at the end
    const uint8_t* tag = encrypted_frame.data() + encrypted_frame.size() - kTagSize;
    
    // Try all keys
    for (auto key : keys) {  // Copy to allow modification
        // Normalize key
        while (key.size() < 32) key.push_back(0);
        if (key.size() > 32) key.resize(32);
        
        size_t decrypted_len = 0;
        if (AesGcmDecrypt(key.data(), key.size(),
                          encrypted_data, encrypted_len, 
                          iv, kIvSize, tag, kTagSize,
                          frame.data(), &decrypted_len)) {
            if (_audioDecryptCount % 100 == 1) {
                LOGI("DecryptAudio SUCCESS: in=%zu, out=%zu", encrypted_frame.size(), decrypted_len);
            }
            CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionSuccess);
            return Result(Status::kOk, decrypted_len);
        }
    }
    
    if (_audioDecryptCount % 100 == 1) {
        LOGW("DecryptAudio failed with all %zu keys", keys.size());
    }
    CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionFailed);
    return Result(Status::kFailedToDecrypt, 0);
}

webrtc::FrameDecryptorInterface::Result CustomFrameDecryptorImpl::DecryptVideo(
    const std::vector<std::vector<uint8_t>>& keys,
    rtc::ArrayView<const uint8_t> encrypted_frame,
    rtc::ArrayView<uint8_t> frame) {
    
    const size_t kTrailerSize = 1 + kIvSize + kTagSize; // 29 bytes
    
    if (encrypted_frame.size() < kTrailerSize) {
        LOGW("DecryptVideo: frame too small: %zu", encrypted_frame.size());
        return Result(Status::kFailedToDecrypt, 0);
    }
    
    // Extract trailer
    size_t trailerOffset = encrypted_frame.size() - kTrailerSize;
    const uint8_t* iv = encrypted_frame.data() + trailerOffset + 1;
    const uint8_t* tag = encrypted_frame.data() + trailerOffset + 1 + kIvSize;
    size_t video_data_size = trailerOffset;
    
    // Try all keys
    for (auto key : keys) {  // Copy to allow modification
        // Normalize key
        while (key.size() < 32) key.push_back(0);
        if (key.size() > 32) key.resize(32);
        
        // First verify GMAC over the encrypted data
        if (!VerifyGmac(key.data(), key.size(), iv, kIvSize, 
                        encrypted_frame.data(), video_data_size, tag, kTagSize)) {
            continue; // Try next key
        }
        
        // GMAC verified! Now decrypt NAL payloads
        // Copy entire frame first (headers stay intact)
        memcpy(frame.data(), encrypted_frame.data(), video_data_size);
        
        // Find NAL units and decrypt payloads
        // Detect codec type
        bool isH265 = false;
        {
            size_t i = 0;
            while (i + 4 < video_data_size) {
                if (encrypted_frame[i] == 0 && encrypted_frame[i+1] == 0) {
                    size_t start_code_len = 0;
                    if (encrypted_frame[i+2] == 1) {
                        start_code_len = 3;
                    } else if (encrypted_frame[i+2] == 0 && encrypted_frame[i+3] == 1) {
                        start_code_len = 4;
                    }
                    if (start_code_len > 0 && i + start_code_len < video_data_size) {
                        uint8_t first_byte = encrypted_frame[i + start_code_len];
                        uint8_t nal_type_h265 = (first_byte >> 1) & 0x3F;
                        if (nal_type_h265 >= 32 && nal_type_h265 <= 40) {
                            isH265 = true;
                        }
                        break;
                    }
                }
                i++;
            }
        }
        
        // Find NAL units using the same parsing logic as encryptor
        std::vector<NalUnitInfo> nalUnits;
        size_t i = 0;
        while (i + 3 < video_data_size) {
            if (encrypted_frame[i] == 0 && encrypted_frame[i+1] == 0) {
                size_t start_code_len = 0;
                if (encrypted_frame[i+2] == 1) {
                    start_code_len = 3;
                } else if (i + 4 <= video_data_size && encrypted_frame[i+2] == 0 && encrypted_frame[i+3] == 1) {
                    start_code_len = 4;
                }
                if (start_code_len > 0) {
                    size_t nal_header_len = isH265 ? 2 : 1;
                    size_t total_header = start_code_len + nal_header_len;
                    if (i + total_header <= video_data_size) {
                        // Extract NAL type
                        uint8_t nal_header_byte = encrypted_frame[i + start_code_len];
                        uint8_t nal_type;
                        if (isH265) {
                            nal_type = (nal_header_byte >> 1) & 0x3F;
                        } else {
                            nal_type = nal_header_byte & 0x1F;
                        }
                        bool should_encrypt = ShouldEncryptNalType(nal_type, isH265);
                        nalUnits.push_back({i, total_header, should_encrypt});
                    }
                    i += start_code_len;
                    continue;
                }
            }
            i++;
        }
        
        if (nalUnits.empty()) {
            // No NAL units found - try full decryption as fallback
            LOGW("DecryptVideo: no NAL units found, passing through");
            CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionSuccess);
            return Result(Status::kOk, video_data_size);
        }
        
        // Decrypt each NAL unit payload with AES-CTR
        // IMPORTANT: Only decrypt VCL NAL units, skip SPS/PPS/VPS
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            LOGE("DecryptVideo: failed to create cipher context");
            return Result(Status::kFailedToDecrypt, 0);
        }
        
        bool success = true;
        uint8_t counter[16] = {0};
        memcpy(counter, iv, kIvSize);
        
        int decryptedNalCount = 0;
        for (size_t j = 0; j < nalUnits.size() && success; j++) {
            // Skip parameter sets - they weren't encrypted
            if (!nalUnits[j].should_encrypt) {
                continue;
            }
            
            size_t nal_start = nalUnits[j].start_offset;
            size_t header_size = nalUnits[j].header_size;
            size_t nal_end = (j + 1 < nalUnits.size()) ? nalUnits[j + 1].start_offset : video_data_size;
            size_t payload_start = nal_start + header_size;
            size_t payload_size = nal_end - payload_start;
            
            if (payload_size > 0) {
                // Set counter for this NAL unit (must match encryptor)
                counter[12] = (j >> 24) & 0xFF;
                counter[13] = (j >> 16) & 0xFF;
                counter[14] = (j >> 8) & 0xFF;
                counter[15] = j & 0xFF;
                
                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), counter) != 1) {
                    success = false;
                    break;
                }
                
                int outLen;
                if (EVP_DecryptUpdate(ctx, 
                                      frame.data() + payload_start,
                                      &outLen,
                                      encrypted_frame.data() + payload_start,
                                      payload_size) != 1) {
                    success = false;
                    break;
                }
                decryptedNalCount++;
            }
        }
        
        EVP_CIPHER_CTX_free(ctx);
        
        if (!success) {
            LOGE("DecryptVideo: AES-CTR decryption failed");
            continue; // Try next key
        }
        
        if (_videoDecryptCount % 50 == 1 || _videoDecryptCount <= 5) {
            LOGI("DecryptVideo SUCCESS: in=%zu, out=%zu, NALs=%zu (decrypted=%d)", 
                 encrypted_frame.size(), video_data_size, nalUnits.size(), decryptedNalCount);
        }
        
        CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionSuccess);
        return Result(Status::kOk, video_data_size);
    }
    
    if (_videoDecryptCount % 50 == 1) {
        LOGW("DecryptVideo failed with all %zu keys", keys.size());
    }
    CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionFailed);
    return Result(Status::kFailedToDecrypt, 0);
}

bool CustomFrameDecryptorImpl::VerifyGmac(const uint8_t* key, size_t key_len,
                                           const uint8_t* iv, size_t iv_len,
                                           const uint8_t* aad, size_t aad_len,
                                           const uint8_t* tag, size_t tag_len) {
    uint8_t computed_tag[16];
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    bool success = false;
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) break;
        
        int outLen;
        if (EVP_EncryptUpdate(ctx, nullptr, &outLen, aad, aad_len) != 1) break;
        
        uint8_t dummy[16];
        if (EVP_EncryptFinal_ex(ctx, dummy, &outLen) != 1) break;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, computed_tag) != 1) break;
        
        success = (memcmp(computed_tag, tag, tag_len) == 0);
    } while (false);
    
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

size_t CustomFrameDecryptorImpl::GetMaxPlaintextByteSize(cricket::MediaType media_type,
                                                          size_t encrypted_frame_size) {
    // For video: original size minus trailer (29 bytes)
    // For audio: original size minus header+IV+TAG
    // Return the larger value to be safe for both cases
    return encrypted_frame_size;
}

bool CustomFrameDecryptorImpl::AesGcmDecrypt(const uint8_t* key, size_t key_len,
                                              const uint8_t* data, size_t len,
                                              const uint8_t* iv, size_t iv_len,
                                              const uint8_t* tag, size_t tag_len,
                                              uint8_t* out, size_t* out_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    
    bool success = false;
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) break;
        
        int outLen;
        if (EVP_DecryptUpdate(ctx, out, &outLen, data, len) != 1) break;
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag) != 1) break;
        
        int finalLen;
        if (EVP_DecryptFinal_ex(ctx, out + outLen, &finalLen) != 1) break;
        
        *out_len = outLen + finalLen;
        success = true;
    } while (false);
    
    EVP_CIPHER_CTX_free(ctx);
    return success;
}

} // namespace tgcalls
