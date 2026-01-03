#ifndef TGCALLS_CUSTOM_FRAME_ENCRYPTOR_IMPL_H
#define TGCALLS_CUSTOM_FRAME_ENCRYPTOR_IMPL_H

#include "api/crypto/frame_encryptor_interface.h"
#include "api/crypto/frame_decryptor_interface.h"
#include "rtc_base/ref_counter.h"
#include "FrameCryptors.h"
#include <memory>

namespace tgcalls {

// Implementation of WebRTC FrameEncryptorInterface
// Delegates all encryption to IFrameEncryptor implementation
class CustomFrameEncryptorImpl : public webrtc::FrameEncryptorInterface {
public:
    CustomFrameEncryptorImpl();
    ~CustomFrameEncryptorImpl() override = default;
    
    void AddRef() const override { ref_count_.IncRef(); }
    rtc::RefCountReleaseStatus Release() const override {
        const auto status = ref_count_.DecRef();
        if (status == rtc::RefCountReleaseStatus::kDroppedLastRef) {
            delete this;
        }
        return status;
    }
    
    int Encrypt(cricket::MediaType media_type,
                uint32_t ssrc,
                rtc::ArrayView<const uint8_t> additional_data,
                rtc::ArrayView<const uint8_t> frame,
                rtc::ArrayView<uint8_t> encrypted_frame,
                size_t* bytes_written) override;
    
    size_t GetMaxCiphertextByteSize(cricket::MediaType media_type,
                                    size_t frame_size) override;

private:
    mutable webrtc::webrtc_impl::RefCounter ref_count_{0};
    
    std::unique_ptr<IFrameEncryptor> _encryptor;
    int _encryptorType = -1;
    
    int _encryptCount = 0;
    int _audioEncryptCount = 0;
    int _videoEncryptCount = 0;
    
    void EnsureEncryptor();
};

// Implementation of WebRTC FrameDecryptorInterface
// Delegates all decryption to IFrameDecryptor implementation
class CustomFrameDecryptorImpl : public webrtc::FrameDecryptorInterface {
public:
    CustomFrameDecryptorImpl();
    ~CustomFrameDecryptorImpl() override = default;
    
    void AddRef() const override { ref_count_.IncRef(); }
    rtc::RefCountReleaseStatus Release() const override {
        const auto status = ref_count_.DecRef();
        if (status == rtc::RefCountReleaseStatus::kDroppedLastRef) {
            delete this;
        }
        return status;
    }
    
    Result Decrypt(cricket::MediaType media_type,
                   const std::vector<uint32_t>& csrcs,
                   rtc::ArrayView<const uint8_t> additional_data,
                   rtc::ArrayView<const uint8_t> encrypted_frame,
                   rtc::ArrayView<uint8_t> frame) override;
    
    size_t GetMaxPlaintextByteSize(cricket::MediaType media_type,
                                   size_t encrypted_frame_size) override;

private:
    mutable webrtc::webrtc_impl::RefCounter ref_count_{0};
    
    // Audio and video may use different encryption types
    std::unique_ptr<IFrameDecryptor> _audioDecryptor;
    std::unique_ptr<IFrameDecryptor> _videoDecryptor;
    
    bool _audioKeyFound = false;
    bool _videoKeyFound = false;
    size_t _lastKeyCount = 0;
    
    int _decryptCount = 0;
    int _audioDecryptCount = 0;
    int _videoDecryptCount = 0;
};

} // namespace tgcalls

#endif // TGCALLS_CUSTOM_FRAME_ENCRYPTOR_IMPL_H
