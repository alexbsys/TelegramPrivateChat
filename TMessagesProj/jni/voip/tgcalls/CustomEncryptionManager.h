#ifndef TGCALLS_CUSTOM_ENCRYPTION_MANAGER_H
#define TGCALLS_CUSTOM_ENCRYPTION_MANAGER_H

#include "api/scoped_refptr.h"
#include <memory>
#include <mutex>
#include <functional>
#include <vector>

namespace tgcalls {

// Forward declarations
class CustomFrameEncryptorImpl;
class CustomFrameDecryptorImpl;

// Encryption status for UI feedback (must match CustomFrameEncryption.h)
enum class EncryptionStatusManager {
    NotYetDetermined,  // Initial state - no packets received yet
    Disabled,          // Unencrypted packets received
    Active,
    DecryptionSuccess,
    DecryptionFailed
};

// Encryption types
enum class EncryptionType {
    AES_256 = 0,
    GOST_28147 = 1,
    AES_256_LITE = 2,   // Fast: only first 64 bytes encrypted, rest XOR
    GOST_28147_LITE = 3 // Fast: only first 64 bytes encrypted, rest XOR
};

// Singleton manager for frame encryption keys
class CustomEncryptionManager {
public:
    static CustomEncryptionManager& getInstance();
    
    // Key management
    void setOutgoingKey(const std::vector<uint8_t>& key);
    void clearOutgoingKey();
    bool hasOutgoingKey() const;
    std::vector<uint8_t> getOutgoingKey() const;
    
    void addIncomingKey(const std::vector<uint8_t>& key);
    void clearIncomingKeys();
    size_t getIncomingKeyCount() const;
    std::vector<std::vector<uint8_t>> getIncomingKeys() const;
    
    // Get encryptor/decryptor instances (they use manager's keys dynamically)
    rtc::scoped_refptr<CustomFrameEncryptorImpl> createEncryptor();
    rtc::scoped_refptr<CustomFrameDecryptorImpl> createDecryptor();
    
    // Status callback for UI
    using StatusCallback = std::function<void(bool isIncoming, EncryptionStatusManager status)>;
    void setStatusCallback(StatusCallback callback);
    void reportStatus(bool isIncoming, EncryptionStatusManager status);
    
    // Get current status for JNI polling
    EncryptionStatusManager getLastIncomingStatus() const;
    
    // Encryption type management
    void setOutgoingEncryptionType(int type);
    int getOutgoingEncryptionType() const;
    int getIncomingEncryptionType() const;
    void setIncomingEncryptionType(int type);
    
private:
    CustomEncryptionManager() = default;
    ~CustomEncryptionManager() = default;
    
    CustomEncryptionManager(const CustomEncryptionManager&) = delete;
    CustomEncryptionManager& operator=(const CustomEncryptionManager&) = delete;
    
    mutable std::mutex _mutex;
    std::vector<uint8_t> _outgoingKey;
    std::vector<std::vector<uint8_t>> _incomingKeys;
    StatusCallback _statusCallback;
    
    // Last reported status to avoid flooding
    EncryptionStatusManager _lastIncomingStatus = EncryptionStatusManager::NotYetDetermined;
    
    // Encryption types
    int _outgoingEncryptionType = 0; // 0 = AES-256, 1 = GOST 28147, 2 = AES LITE, 3 = GOST LITE
    int _incomingEncryptionType = -1; // -1 = not yet determined, 0-3 = detected from incoming frames
};

} // namespace tgcalls

#endif // TGCALLS_CUSTOM_ENCRYPTION_MANAGER_H
