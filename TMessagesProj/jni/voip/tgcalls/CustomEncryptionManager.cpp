#include "CustomEncryptionManager.h"
#include "CustomFrameEncryptorImpl.h"
#include <android/log.h>

#define LOG_TAG "CustomEncryptionManager"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

namespace tgcalls {

CustomEncryptionManager& CustomEncryptionManager::getInstance() {
    static CustomEncryptionManager instance;
    return instance;
}

void CustomEncryptionManager::setOutgoingKey(const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(_mutex);
    _outgoingKey = key;
    LOGI("setOutgoingKey: key set, size=%zu", key.size());
}

void CustomEncryptionManager::clearOutgoingKey() {
    std::lock_guard<std::mutex> lock(_mutex);
    _outgoingKey.clear();
    LOGI("clearOutgoingKey: key cleared");
}

bool CustomEncryptionManager::hasOutgoingKey() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return !_outgoingKey.empty();
}

std::vector<uint8_t> CustomEncryptionManager::getOutgoingKey() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _outgoingKey;
}

void CustomEncryptionManager::addIncomingKey(const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(_mutex);
    _incomingKeys.push_back(key);
    LOGI("addIncomingKey: key added, total=%zu", _incomingKeys.size());
}

void CustomEncryptionManager::clearIncomingKeys() {
    std::lock_guard<std::mutex> lock(_mutex);
    _incomingKeys.clear();
    _lastIncomingStatus = EncryptionStatusManager::NotYetDetermined;
    _incomingEncryptionType = -1; // Reset to "not yet determined"
    LOGI("clearIncomingKeys: keys cleared, encryption type reset");
}

size_t CustomEncryptionManager::getIncomingKeyCount() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _incomingKeys.size();
}

std::vector<std::vector<uint8_t>> CustomEncryptionManager::getIncomingKeys() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _incomingKeys;
}

void CustomEncryptionManager::setStatusCallback(StatusCallback callback) {
    std::lock_guard<std::mutex> lock(_mutex);
    _statusCallback = callback;
}

void CustomEncryptionManager::reportStatus(bool isIncoming, EncryptionStatusManager status) {
    StatusCallback callback;
    bool shouldReport = false;
    
    {
        std::lock_guard<std::mutex> lock(_mutex);
        if (isIncoming) {
            if (_lastIncomingStatus != status) {
                _lastIncomingStatus = status;
                shouldReport = true;
            }
        } else {
            shouldReport = true; // Always report outgoing status changes
        }
        callback = _statusCallback;
    }
    
    if (shouldReport && callback) {
        callback(isIncoming, status);
    }
}

rtc::scoped_refptr<CustomFrameEncryptorImpl> CustomEncryptionManager::createEncryptor() {
    LOGI("createEncryptor: creating new encryptor (will use manager keys dynamically)");
    return rtc::scoped_refptr<CustomFrameEncryptorImpl>(new CustomFrameEncryptorImpl());
}

rtc::scoped_refptr<CustomFrameDecryptorImpl> CustomEncryptionManager::createDecryptor() {
    LOGI("createDecryptor: creating new decryptor (will use manager keys dynamically)");
    return rtc::scoped_refptr<CustomFrameDecryptorImpl>(new CustomFrameDecryptorImpl());
}

EncryptionStatusManager CustomEncryptionManager::getLastIncomingStatus() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _lastIncomingStatus;
}

void CustomEncryptionManager::setOutgoingEncryptionType(int type) {
    std::lock_guard<std::mutex> lock(_mutex);
    _outgoingEncryptionType = type;
    LOGI("setOutgoingEncryptionType: type=%d (%s)", type, type == 0 ? "AES-256" : "GOST 28147");
}

int CustomEncryptionManager::getOutgoingEncryptionType() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _outgoingEncryptionType;
}

int CustomEncryptionManager::getIncomingEncryptionType() const {
    std::lock_guard<std::mutex> lock(_mutex);
    return _incomingEncryptionType;
}

void CustomEncryptionManager::setIncomingEncryptionType(int type) {
    std::lock_guard<std::mutex> lock(_mutex);
    _incomingEncryptionType = type;
}

} // namespace tgcalls
