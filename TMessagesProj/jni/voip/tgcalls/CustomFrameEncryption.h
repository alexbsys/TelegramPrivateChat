#ifndef TGCALLS_CUSTOM_FRAME_ENCRYPTION_H
#define TGCALLS_CUSTOM_FRAME_ENCRYPTION_H

#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>

namespace tgcalls {

// Magic bytes to identify encrypted frames
static const uint8_t ENCRYPTED_FRAME_MAGIC[4] = {0xCF, 0xE1, 0x01, 0x00};

// Status callback types
enum class EncryptionStatus {
    Disabled,
    Active,
    DecryptionFailed,
    DecryptionSuccess
};

class CustomFrameEncryption {
public:
    static CustomFrameEncryption& getInstance();
    
    // Set outgoing encryption key (from password)
    void setOutgoingKey(const uint8_t* key, size_t keyLen);
    void clearOutgoingKey();
    bool hasOutgoingKey() const;
    
    // Add incoming decryption key
    void addIncomingKey(const uint8_t* key, size_t keyLen);
    void clearIncomingKeys();
    size_t getIncomingKeyCount() const;
    
    // Encrypt outgoing RTP payload
    // Returns encrypted data, or empty if no key set (pass through)
    std::vector<uint8_t> encryptFrame(const uint8_t* data, size_t len);
    
    // Decrypt incoming RTP payload
    // Returns decrypted data, or original if not encrypted or decryption fails
    // Sets decrypted to true if successfully decrypted
    std::vector<uint8_t> decryptFrame(const uint8_t* data, size_t len, bool& decrypted, bool& wasEncrypted);
    
    // Status callbacks
    void setStatusCallback(std::function<void(bool outgoing, EncryptionStatus status)> callback);
    
    // Check if frame is encrypted (has magic header)
    static bool isEncryptedFrame(const uint8_t* data, size_t len);
    
private:
    CustomFrameEncryption();
    ~CustomFrameEncryption();
    
    // AES-GCM encryption/decryption using OpenSSL
    std::vector<uint8_t> aesGcmEncrypt(const uint8_t* key, const uint8_t* data, size_t len);
    std::vector<uint8_t> aesGcmDecrypt(const uint8_t* key, const uint8_t* data, size_t len, bool& success);
    
    // Generate random IV
    void generateIV(uint8_t* iv, size_t len);
    
    mutable std::mutex _mutex;
    
    std::vector<uint8_t> _outgoingKey;
    std::vector<std::vector<uint8_t>> _incomingKeys;
    
    std::function<void(bool outgoing, EncryptionStatus status)> _statusCallback;
    
    // Track last status to avoid spamming callbacks
    EncryptionStatus _lastOutgoingStatus = EncryptionStatus::Disabled;
    EncryptionStatus _lastIncomingStatus = EncryptionStatus::Disabled;
};

} // namespace tgcalls

#endif // TGCALLS_CUSTOM_FRAME_ENCRYPTION_H


