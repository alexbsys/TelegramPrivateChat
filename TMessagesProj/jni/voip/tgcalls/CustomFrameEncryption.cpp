#include "CustomFrameEncryption.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <android/log.h>

#define LOG_TAG "CustomFrameEncryption"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace tgcalls {

static const size_t AES_KEY_SIZE = 32;  // 256 bits
static const size_t IV_SIZE = 12;        // GCM recommended IV size
static const size_t TAG_SIZE = 16;       // GCM auth tag size
static const size_t MAGIC_SIZE = sizeof(ENCRYPTED_FRAME_MAGIC);

CustomFrameEncryption& CustomFrameEncryption::getInstance() {
    static CustomFrameEncryption instance;
    return instance;
}

CustomFrameEncryption::CustomFrameEncryption() {
}

CustomFrameEncryption::~CustomFrameEncryption() {
}

void CustomFrameEncryption::setOutgoingKey(const uint8_t* key, size_t keyLen) {
    std::lock_guard<std::mutex> lock(_mutex);
    _outgoingKey.assign(key, key + std::min(keyLen, AES_KEY_SIZE));
    // Pad to 32 bytes if needed
    while (_outgoingKey.size() < AES_KEY_SIZE) {
        _outgoingKey.push_back(0);
    }
    _lastOutgoingStatus = EncryptionStatus::Active;
    LOGI("setOutgoingKey: key set, len=%zu, padded to %zu", keyLen, _outgoingKey.size());
    if (_statusCallback) {
        _statusCallback(true, EncryptionStatus::Active);
    }
}

void CustomFrameEncryption::clearOutgoingKey() {
    std::lock_guard<std::mutex> lock(_mutex);
    _outgoingKey.clear();
    _lastOutgoingStatus = EncryptionStatus::Disabled;
    if (_statusCallback) {
        _statusCallback(true, EncryptionStatus::Disabled);
    }
}

bool CustomFrameEncryption::hasOutgoingKey() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return !_outgoingKey.empty();
}

void CustomFrameEncryption::addIncomingKey(const uint8_t* key, size_t keyLen) {
    std::lock_guard<std::mutex> lock(_mutex);
    std::vector<uint8_t> keyVec(key, key + std::min(keyLen, AES_KEY_SIZE));
    while (keyVec.size() < AES_KEY_SIZE) {
        keyVec.push_back(0);
    }
    _incomingKeys.push_back(std::move(keyVec));
    LOGI("addIncomingKey: added key, len=%zu, total keys=%zu", keyLen, _incomingKeys.size());
}

void CustomFrameEncryption::clearIncomingKeys() {
    std::lock_guard<std::mutex> lock(_mutex);
    _incomingKeys.clear();
}

size_t CustomFrameEncryption::getIncomingKeyCount() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _incomingKeys.size();
}

void CustomFrameEncryption::setStatusCallback(std::function<void(bool outgoing, EncryptionStatus status)> callback) {
    std::lock_guard<std::mutex> lock(_mutex);
    _statusCallback = std::move(callback);
}

bool CustomFrameEncryption::isEncryptedFrame(const uint8_t* data, size_t len) {
    if (len < MAGIC_SIZE) {
        return false;
    }
    return memcmp(data, ENCRYPTED_FRAME_MAGIC, MAGIC_SIZE) == 0;
}

void CustomFrameEncryption::generateIV(uint8_t* iv, size_t len) {
    RAND_bytes(iv, len);
}

std::vector<uint8_t> CustomFrameEncryption::aesGcmEncrypt(const uint8_t* key, const uint8_t* data, size_t len) {
    std::vector<uint8_t> result;
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return result;
    }
    
    uint8_t iv[IV_SIZE];
    generateIV(iv, IV_SIZE);
    
    // Output format: MAGIC + IV + ENCRYPTED_DATA + TAG
    result.resize(MAGIC_SIZE + IV_SIZE + len + TAG_SIZE);
    
    // Copy magic bytes
    memcpy(result.data(), ENCRYPTED_FRAME_MAGIC, MAGIC_SIZE);
    // Copy IV
    memcpy(result.data() + MAGIC_SIZE, iv, IV_SIZE);
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    int outLen;
    if (EVP_EncryptUpdate(ctx, result.data() + MAGIC_SIZE + IV_SIZE, &outLen, data, len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    int finalLen;
    if (EVP_EncryptFinal_ex(ctx, result.data() + MAGIC_SIZE + IV_SIZE + outLen, &finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Get the auth tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, result.data() + MAGIC_SIZE + IV_SIZE + outLen + finalLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    result.resize(MAGIC_SIZE + IV_SIZE + outLen + finalLen + TAG_SIZE);
    
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::vector<uint8_t> CustomFrameEncryption::aesGcmDecrypt(const uint8_t* key, const uint8_t* data, size_t len, bool& success) {
    success = false;
    std::vector<uint8_t> result;
    
    // Data format: MAGIC + IV + ENCRYPTED_DATA + TAG
    if (len < MAGIC_SIZE + IV_SIZE + TAG_SIZE) {
        return result;
    }
    
    // Skip magic, extract IV
    const uint8_t* iv = data + MAGIC_SIZE;
    const uint8_t* encrypted = data + MAGIC_SIZE + IV_SIZE;
    size_t encryptedLen = len - MAGIC_SIZE - IV_SIZE - TAG_SIZE;
    const uint8_t* tag = data + len - TAG_SIZE;
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return result;
    }
    
    result.resize(encryptedLen);
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    int outLen;
    if (EVP_DecryptUpdate(ctx, result.data(), &outLen, encrypted, encryptedLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return {};
    }
    
    int finalLen;
    int ret = EVP_DecryptFinal_ex(ctx, result.data() + outLen, &finalLen);
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret != 1) {
        // Tag verification failed - wrong key
        return {};
    }
    
    result.resize(outLen + finalLen);
    success = true;
    return result;
}

std::vector<uint8_t> CustomFrameEncryption::encryptFrame(const uint8_t* data, size_t len) {
    static int encryptCallCount = 0;
    encryptCallCount++;
    
    if (encryptCallCount % 500 == 1) {
        LOGI("encryptFrame CALLED: len=%zu, call#=%d", len, encryptCallCount);
    }
    
    std::lock_guard<std::mutex> lock(_mutex);
    
    if (_outgoingKey.empty()) {
        // No encryption - return empty to indicate pass through
        if (encryptCallCount % 500 == 1) {
            LOGI("encryptFrame: NO outgoing key, returning empty");
        }
        return {};
    }
    
    if (encryptCallCount % 500 == 1) {
        LOGI("encryptFrame: have outgoing key, encrypting %zu bytes", len);
    }
    
    auto result = aesGcmEncrypt(_outgoingKey.data(), data, len);
    if (!result.empty()) {
        static int encryptCount = 0;
        if (encryptCount++ % 1000 == 0) {
            LOGI("encryptFrame: encrypted %zu bytes -> %zu bytes (count=%d)", len, result.size(), encryptCount);
        }
    } else {
        LOGE("encryptFrame: encryption failed for %zu bytes", len);
    }
    return result;
}

std::vector<uint8_t> CustomFrameEncryption::decryptFrame(const uint8_t* data, size_t len, bool& decrypted, bool& wasEncrypted) {
    decrypted = false;
    wasEncrypted = isEncryptedFrame(data, len);
    
    if (!wasEncrypted) {
        // Not encrypted - return original data
        static int unencryptedCount = 0;
        if (unencryptedCount++ % 1000 == 0) {
            LOGI("decryptFrame: unencrypted packet %zu bytes (count=%d)", len, unencryptedCount);
        }
        return std::vector<uint8_t>(data, data + len);
    }
    
    LOGI("decryptFrame: detected encrypted packet %zu bytes, trying %zu keys", len, _incomingKeys.size());
    
    std::lock_guard<std::mutex> lock(_mutex);
    
    // Try all incoming keys
    for (const auto& key : _incomingKeys) {
        bool success = false;
        auto result = aesGcmDecrypt(key.data(), data, len, success);
        if (success) {
            decrypted = true;
            LOGI("decryptFrame: successfully decrypted %zu bytes -> %zu bytes", len, result.size());
            
            // Update status if changed
            if (_lastIncomingStatus != EncryptionStatus::DecryptionSuccess) {
                _lastIncomingStatus = EncryptionStatus::DecryptionSuccess;
                if (_statusCallback) {
                    _statusCallback(false, EncryptionStatus::DecryptionSuccess);
                }
            }
            
            return result;
        }
    }
    
    // Decryption failed with all keys
    LOGW("decryptFrame: decryption failed for %zu bytes with all %zu keys", len, _incomingKeys.size());
    if (_lastIncomingStatus != EncryptionStatus::DecryptionFailed) {
        _lastIncomingStatus = EncryptionStatus::DecryptionFailed;
        if (_statusCallback) {
            _statusCallback(false, EncryptionStatus::DecryptionFailed);
        }
    }
    
    // Return empty to indicate failure
    return {};
}

} // namespace tgcalls

