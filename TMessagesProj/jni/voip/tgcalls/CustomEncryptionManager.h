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
    Disabled,
    Active,
    DecryptionSuccess,
    DecryptionFailed
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
    EncryptionStatusManager _lastIncomingStatus = EncryptionStatusManager::Disabled;
};

} // namespace tgcalls

#endif // TGCALLS_CUSTOM_ENCRYPTION_MANAGER_H
