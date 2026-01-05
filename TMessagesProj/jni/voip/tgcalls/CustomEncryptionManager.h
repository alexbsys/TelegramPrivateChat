#ifndef TGCALLS_CUSTOM_ENCRYPTION_MANAGER_H
#define TGCALLS_CUSTOM_ENCRYPTION_MANAGER_H

#include "api/scoped_refptr.h"
#include <memory>
#include <mutex>
#include <functional>
#include <vector>
#include <atomic>

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
    
    // Traffic stats tracking
    void addBytesSent(size_t bytes, bool isAudio);
    void addBytesReceived(size_t bytes, bool isAudio);
    void getTrafficStats(uint64_t& sent, uint64_t& received, uint64_t& audioSent, uint64_t& audioReceived) const;
    void resetTrafficStats();
    
    // Video codec detection
    void setIncomingVideoCodec(int codecType);  // 0=Unknown, 1=H.264, 2=H.265, 3=VP8, 4=VP9
    int getIncomingVideoCodec() const;
    
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
    
    // Traffic stats
    std::atomic<uint64_t> _bytesSent{0};
    std::atomic<uint64_t> _bytesReceived{0};
    std::atomic<uint64_t> _audioBytesSent{0};
    std::atomic<uint64_t> _audioBytesReceived{0};
    
    // Video codec
    std::atomic<int> _incomingVideoCodec{0}; // 0=Unknown, 1=H.264, 2=H.265, 3=VP8, 4=VP9
};

} // namespace tgcalls

#endif // TGCALLS_CUSTOM_ENCRYPTION_MANAGER_H
