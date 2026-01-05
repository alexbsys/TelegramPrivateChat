#include "CustomFrameEncryptorImpl.h"
#include "CustomEncryptionManager.h"
#include <android/log.h>
#include <cstring>

#define LOG_TAG "CustomFrameEncryptor"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace tgcalls {

// ==================== CustomFrameEncryptorImpl ====================

CustomFrameEncryptorImpl::CustomFrameEncryptorImpl() {
    LOGI("CustomFrameEncryptorImpl created");
}

void CustomFrameEncryptorImpl::EnsureEncryptor() {
    auto key = CustomEncryptionManager::getInstance().getOutgoingKey();
    int encType = CustomEncryptionManager::getInstance().getOutgoingEncryptionType();
    
    if (key.empty()) {
        _encryptor.reset();
        _encryptorType = -1;
        return;
    }
    
    // Create or recreate encryptor if type changed
    if (!_encryptor || _encryptorType != encType) {
        _encryptor = CryptorFactory::CreateEncryptor(encType);
        _encryptorType = encType;
        if (_encryptor) {
            _encryptor->SetKey(key);
            LOGI("Created encryptor type %d", encType);
        }
    } else {
        // Update key if encryptor exists
        _encryptor->SetKey(key);
    }
}

int CustomFrameEncryptorImpl::Encrypt(
    cricket::MediaType media_type,
    uint32_t ssrc,
    rtc::ArrayView<const uint8_t> additional_data,
    rtc::ArrayView<const uint8_t> frame,
    rtc::ArrayView<uint8_t> encrypted_frame,
    size_t* bytes_written) {
    
    _encryptCount++;
    
    auto key = CustomEncryptionManager::getInstance().getOutgoingKey();
    if (key.empty()) {
        // No encryption - pass through
        if (encrypted_frame.size() >= frame.size()) {
            memcpy(encrypted_frame.data(), frame.data(), frame.size());
            *bytes_written = frame.size();
            return 0;
        }
        return 1;
    }
    
    EnsureEncryptor();
    if (!_encryptor) {
        LOGE("Encrypt: failed to create encryptor");
        return 1;
    }
    
    CryptResult result(false, 0);
    
    if (media_type == cricket::MediaType::MEDIA_TYPE_VIDEO) {
        _videoEncryptCount++;
        result = _encryptor->EncryptVideo(
            frame.data(), frame.size(),
            encrypted_frame.data(), encrypted_frame.size());
        
        if (result.success && (_videoEncryptCount <= 3 || _videoEncryptCount % 1000 == 0)) {
            LOGI("EncryptVideo[%d]: %zu -> %zu bytes, type=%d", 
                 _videoEncryptCount, frame.size(), result.bytesWritten, _encryptor->GetEncryptionTypeId());
        }
    } else {
        _audioEncryptCount++;
        result = _encryptor->EncryptAudio(
            frame.data(), frame.size(),
            encrypted_frame.data(), encrypted_frame.size());
        
        if (result.success && (_audioEncryptCount <= 3 || _audioEncryptCount % 1000 == 0)) {
            LOGI("EncryptAudio[%d]: %zu -> %zu bytes, type=%d", 
                 _audioEncryptCount, frame.size(), result.bytesWritten, _encryptor->GetEncryptionTypeId());
        }
    }
    
    if (result.success) {
        *bytes_written = result.bytesWritten;
        // Track bytes sent
        CustomEncryptionManager::getInstance().addBytesSent(
            result.bytesWritten, 
            media_type == cricket::MediaType::MEDIA_TYPE_AUDIO);
        return 0;
    }
    
    LOGE("Encrypt: failed");
    return 1;
}

size_t CustomFrameEncryptorImpl::GetMaxCiphertextByteSize(
    cricket::MediaType media_type, size_t frame_size) {
    
    EnsureEncryptor();
    if (!_encryptor) {
        // Fallback - assume worst case
        return (frame_size * 2) + 64;
    }
    
    if (media_type == cricket::MediaType::MEDIA_TYPE_VIDEO) {
        return _encryptor->GetMaxVideoCiphertextSize(frame_size);
    } else {
        return _encryptor->GetMaxAudioCiphertextSize(frame_size);
    }
}

// ==================== CustomFrameDecryptorImpl ====================

CustomFrameDecryptorImpl::CustomFrameDecryptorImpl() {
    LOGI("CustomFrameDecryptorImpl created");
}

// Helper to de-escape RBSP (remove emulation prevention bytes)
static size_t DeescapeRbsp(const uint8_t* src, size_t srcSize, uint8_t* dst, size_t dstMaxSize) {
    size_t srcPos = 0, dstPos = 0;
    int zeroCount = 0;
    
    while (srcPos < srcSize && dstPos < dstMaxSize) {
        uint8_t byte = src[srcPos++];
        
        if (zeroCount >= 2 && byte == 0x03 && srcPos < srcSize) {
            uint8_t nextByte = src[srcPos];
            if (nextByte <= 3) {
                zeroCount = 0;
                continue;  // Skip the 0x03 emulation prevention byte
            }
        }
        
        dst[dstPos++] = byte;
        
        if (byte == 0) zeroCount++;
        else zeroCount = 0;
    }
    
    return dstPos;
}

// Helper to find SEI NAL with our UUID and extract magic byte
static uint8_t FindSeiMagicByte(const uint8_t* data, size_t size) {
    // Our custom UUID
    static constexpr uint8_t kSeiUuid[16] = {
        0xC1, 0x9E, 0x6C, 0x8F, 0x24, 0x5A, 0x4B, 0x7D,
        0x8E, 0x3F, 0x2A, 0x1B, 0x0C, 0x4D, 0x5E, 0x6F
    };
    
    size_t i = 0;
    while (i + 30 < size) {
        // Find start code
        if (data[i] == 0 && data[i+1] == 0) {
            size_t startCodeLen = 0;
            if (data[i+2] == 1) {
                startCodeLen = 3;
            } else if (data[i+2] == 0 && i + 3 < size && data[i+3] == 1) {
                startCodeLen = 4;
            }
            
            if (startCodeLen > 0) {
                size_t headerPos = i + startCodeLen;
                if (headerPos >= size) break;
                
                uint8_t nalByte = data[headerPos];
                
                // Check if SEI NAL (type 6 for H.264, 39/40 for H.265)
                bool isSei = false;
                size_t nalHeaderSize = 1;
                if ((nalByte & 0x80) == 0) {
                    uint8_t h264Type = nalByte & 0x1F;
                    uint8_t h265Type = (nalByte >> 1) & 0x3F;
                    if (h264Type == 6) {
                        isSei = true;
                    } else if (h265Type == 39 || h265Type == 40) {
                        isSei = true;
                        nalHeaderSize = 2;
                    }
                }
                
                if (isSei) {
                    size_t pos = headerPos + nalHeaderSize;
                    if (pos >= size) { i++; continue; }
                    
                    // Check payload type (should be 5 = user_data_unregistered)
                    if (data[pos] != 0x05) { i++; continue; }
                    pos++;
                    
                    // Parse payload size
                    size_t payloadSize = 0;
                    while (pos < size && data[pos] == 0xFF) {
                        payloadSize += 255;
                        pos++;
                    }
                    if (pos >= size) { i++; continue; }
                    payloadSize += data[pos++];
                    
                    // Need enough data for UUID + seq_num + magic (at least 21 bytes)
                    size_t remainingData = size - pos;
                    if (remainingData < 21) { i++; continue; }
                    
                    // De-escape the payload to correctly read magic byte
                    uint8_t deescaped[64];
                    size_t deescapedSize = DeescapeRbsp(data + pos, remainingData, deescaped, sizeof(deescaped));
                    
                    if (deescapedSize < 21) { i++; continue; }
                    
                    // Check if our UUID at start of payload
                    if (memcmp(deescaped, kSeiUuid, 16) == 0) {
                        // Found our SEI! Magic byte is at offset 16 (UUID) + 4 (seq_num) = 20
                        uint8_t magic = deescaped[20];
                        if (magic != 0) {
                            return magic;
                        }
                    }
                }
                
                i = headerPos + 1;
                continue;
            }
        }
        i++;
    }
    return 0;  // Not found
}

// Helper to detect video codec from NAL units
// Sets: 0=Unknown, 1=H.264, 2=H.265, 3=VP8, 4=VP9
static void DetectAndSetVideoCodec(const uint8_t* data, size_t size) {
    if (size < 5) return;
    
    // Look for NAL unit start code
    for (size_t i = 0; i + 4 < size; i++) {
        bool found3 = (data[i] == 0x00 && data[i+1] == 0x00 && data[i+2] == 0x01);
        bool found4 = (i + 4 < size && data[i] == 0x00 && data[i+1] == 0x00 && 
                       data[i+2] == 0x00 && data[i+3] == 0x01);
        
        if (found4 || found3) {
            size_t nalPos = found4 ? i + 4 : i + 3;
            if (nalPos >= size) return;
            
            uint8_t nalByte = data[nalPos];
            uint8_t forbiddenBit = (nalByte >> 7) & 0x01;
            
            if (forbiddenBit == 0) {
                // Check if it looks like H.264 or H.265
                // H.264: forbidden_zero_bit(1) + nal_ref_idc(2) + nal_unit_type(5)
                // H.265: forbidden_zero_bit(1) + nal_unit_type(6) + nuh_layer_id(6) + nuh_temporal_id_plus1(3)
                
                uint8_t h264Type = nalByte & 0x1F;
                
                // Check second byte for H.265 marker
                if (nalPos + 1 < size) {
                    uint8_t secondByte = data[nalPos + 1];
                    // H.265 has specific patterns in the second byte (layer_id and temporal_id)
                    // nuh_layer_id is 6 bits, typically 0 for base layer
                    // nuh_temporal_id_plus1 is 3 bits, must be > 0
                    uint8_t layerId = secondByte >> 3;
                    uint8_t tempIdPlus1 = secondByte & 0x07;
                    
                    if (layerId == 0 && tempIdPlus1 >= 1 && tempIdPlus1 <= 7) {
                        // Likely H.265
                        uint8_t h265Type = (nalByte >> 1) & 0x3F;
                        // VPS=32, SPS=33, PPS=34, IDR=19/20, TRAIL=1
                        if (h265Type == 32 || h265Type == 33 || h265Type == 34 ||
                            h265Type == 19 || h265Type == 20 || h265Type == 1) {
                            CustomEncryptionManager::getInstance().setIncomingVideoCodec(2); // H.265
                            return;
                        }
                    }
                }
                
                // Check for H.264 NAL types
                // SPS=7, PPS=8, IDR=5, non-IDR=1
                if (h264Type == 7 || h264Type == 8 || h264Type == 5 || h264Type == 1) {
                    CustomEncryptionManager::getInstance().setIncomingVideoCodec(1); // H.264
                    return;
                }
            }
            return;
        }
    }
    
    // VP8 check: starts with specific bytes
    if (size >= 3 && (data[0] & 0x01) == 0) {
        // VP8 keyframe starts with 0x9d 0x01 0x2a (after the 3-byte frame tag)
        if (size >= 10) {
            if (data[3] == 0x9d && data[4] == 0x01 && data[5] == 0x2a) {
                CustomEncryptionManager::getInstance().setIncomingVideoCodec(3); // VP8
                return;
            }
        }
    }
    
    // VP9 check
    if (size >= 2) {
        // VP9 frames start with specific profile/show bits
        uint8_t profile = (data[0] >> 4) & 0x03;
        if (profile <= 3) {
            // Could be VP9, but need more validation
            // For now, leave as unknown if not H.264/H.265
        }
    }
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
    
    if (encrypted_frame.empty()) {
        return Result(Status::kFailedToDecrypt, 0);
    }
    
    // For audio: magic byte is at the start
    uint8_t firstByte = encrypted_frame[0];
    
    // For video: SEI-based - find SEI NAL with our UUID and extract magic byte
    // SEI format: [START_CODE][SEI_HEADER][payloadType=5][payloadSize][UUID 16B][SEQ_NUM 4B][MAGIC][...]
    uint8_t videoMagic = 0;
    
    if (isVideo && encrypted_frame.size() > 30) {
        videoMagic = FindSeiMagicByte(encrypted_frame.data(), encrypted_frame.size());
    }
    
    bool isKnownAudio = CryptorFactory::IsKnownAudioMagic(firstByte);
    bool isKnownVideo = CryptorFactory::IsKnownVideoMagic(videoMagic);
    
    if (!isKnownAudio && !isKnownVideo) {
        // Not encrypted - pass through
        if (frame.size() >= encrypted_frame.size()) {
            memcpy(frame.data(), encrypted_frame.data(), encrypted_frame.size());
            CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::Disabled);
            // Track bytes received (unencrypted)
            CustomEncryptionManager::getInstance().addBytesReceived(encrypted_frame.size(), !isVideo);
            // Detect video codec for unencrypted streams
            if (isVideo && encrypted_frame.size() > 4) {
                DetectAndSetVideoCodec(encrypted_frame.data(), encrypted_frame.size());
            }
            return Result(Status::kOk, encrypted_frame.size());
        }
        return Result(Status::kFailedToDecrypt, 0);
    }
    
    auto keys = CustomEncryptionManager::getInstance().getIncomingKeys();
    if (keys.empty()) {
        if (_decryptCount <= 5) {
            LOGW("Decrypt: no keys available");
        }
        CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionFailed);
        return Result(Status::kFailedToDecrypt, 0);
    }
    
    IFrameDecryptor* decryptor = nullptr;
    bool* keyFound = nullptr;
    
    if (isVideo && isKnownVideo) {
        // Video decryption
        if (!_videoDecryptor) {
            _videoDecryptor = CryptorFactory::CreateDecryptorByVideoMagic(videoMagic);
            if (_videoDecryptor) {
                LOGI("Created video decryptor for magic 0x%02X", videoMagic);
            }
        }
        decryptor = _videoDecryptor.get();
        keyFound = &_videoKeyFound;
    } else if (isKnownAudio) {
        // Audio decryption
        if (!_audioDecryptor) {
            _audioDecryptor = CryptorFactory::CreateDecryptorByAudioMagic(firstByte);
            if (_audioDecryptor) {
                LOGI("Created audio decryptor for magic 0x%02X", firstByte);
            }
        }
        decryptor = _audioDecryptor.get();
        keyFound = &_audioKeyFound;
    }
    
    if (!decryptor) {
        LOGE("Failed to create decryptor");
        CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionFailed);
        return Result(Status::kFailedToDecrypt, 0);
    }
    
    // Find key if not found or key list changed
    if (!*keyFound || keys.size() != _lastKeyCount) {
        int keyIdx;
        if (isVideo) {
            keyIdx = decryptor->TryFindVideoKey(keys, encrypted_frame.data(), encrypted_frame.size());
        } else {
            keyIdx = decryptor->TryFindAudioKey(keys, encrypted_frame.data(), encrypted_frame.size());
        }
        
        if (keyIdx >= 0) {
            decryptor->SetKey(keys[keyIdx]);
            *keyFound = true;
            _lastKeyCount = keys.size();
            LOGI("%s key found at index %d", isVideo ? "Video" : "Audio", keyIdx);
        } else {
            CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionFailed);
            return Result(Status::kFailedToDecrypt, 0);
        }
    }
    
    // Decrypt
    CryptResult result(false, 0);
    if (isVideo) {
        result = decryptor->DecryptVideo(
            encrypted_frame.data(), encrypted_frame.size(),
            frame.data(), frame.size());
    } else {
        result = decryptor->DecryptAudio(
            encrypted_frame.data(), encrypted_frame.size(),
            frame.data(), frame.size());
    }
    
    if (result.success) {
        if (isVideo) {
            if (_videoDecryptCount <= 3 || _videoDecryptCount % 1000 == 0) {
                LOGI("DecryptVideo[%d]: %zu -> %zu bytes, type=%d", 
                     _videoDecryptCount, encrypted_frame.size(), result.bytesWritten, 
                     decryptor->GetEncryptionTypeId());
            }
        } else {
            if (_audioDecryptCount <= 3 || _audioDecryptCount % 1000 == 0) {
                LOGI("DecryptAudio[%d]: %zu -> %zu bytes, type=%d", 
                     _audioDecryptCount, encrypted_frame.size(), result.bytesWritten,
                     decryptor->GetEncryptionTypeId());
            }
        }
        
        CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionSuccess);
        CustomEncryptionManager::getInstance().setIncomingEncryptionType(decryptor->GetEncryptionTypeId());
        // Track bytes received
        CustomEncryptionManager::getInstance().addBytesReceived(encrypted_frame.size(), !isVideo);
        // Detect video codec from decrypted stream
        if (isVideo && result.bytesWritten > 4) {
            DetectAndSetVideoCodec(frame.data(), result.bytesWritten);
        }
        return Result(Status::kOk, result.bytesWritten);
    }
    
    // Decryption failed - key might have become invalid
    *keyFound = false;
    CustomEncryptionManager::getInstance().reportStatus(true, EncryptionStatusManager::DecryptionFailed);
    return Result(Status::kFailedToDecrypt, 0);
}

size_t CustomFrameDecryptorImpl::GetMaxPlaintextByteSize(
    cricket::MediaType media_type, size_t encrypted_frame_size) {
    return encrypted_frame_size;
}

} // namespace tgcalls
