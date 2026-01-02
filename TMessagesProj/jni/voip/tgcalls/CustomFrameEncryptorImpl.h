#ifndef TGCALLS_CUSTOM_FRAME_ENCRYPTOR_IMPL_H
#define TGCALLS_CUSTOM_FRAME_ENCRYPTOR_IMPL_H

#include "api/crypto/frame_encryptor_interface.h"
#include "api/crypto/frame_decryptor_interface.h"
#include "rtc_base/ref_counter.h"
#include <vector>
#include <mutex>

namespace tgcalls {

// Forward declaration
class CustomEncryptionManager;

// Implementation of WebRTC FrameEncryptorInterface for custom encryption
// Gets keys dynamically from CustomEncryptionManager
class CustomFrameEncryptorImpl : public webrtc::FrameEncryptorInterface {
public:
    CustomFrameEncryptorImpl();
    ~CustomFrameEncryptorImpl() override = default;
    
    // RefCountInterface implementation
    void AddRef() const override { ref_count_.IncRef(); }
    rtc::RefCountReleaseStatus Release() const override {
        const auto status = ref_count_.DecRef();
        if (status == rtc::RefCountReleaseStatus::kDroppedLastRef) {
            delete this;
        }
        return status;
    }
    
    // FrameEncryptorInterface implementation
    int Encrypt(cricket::MediaType media_type,
                uint32_t ssrc,
                rtc::ArrayView<const uint8_t> additional_data,
                rtc::ArrayView<const uint8_t> frame,
                rtc::ArrayView<uint8_t> encrypted_frame,
                size_t* bytes_written) override;
    
    size_t GetMaxCiphertextByteSize(cricket::MediaType media_type,
                                    size_t frame_size) override;

private:
    static const uint8_t kMagicByte = 0xCE;      // Audio encryption marker
    static const uint8_t kVideoMagicByte = 0xE1; // Video encryption marker (NAL-preserving)
    static const size_t kIvSize = 12;
    static const size_t kTagSize = 16;
    
    mutable webrtc::webrtc_impl::RefCounter ref_count_{0};
    int _encryptCount = 0;
    int _audioEncryptCount = 0;
    int _videoEncryptCount = 0;
    
    // Full frame encryption for audio
    int EncryptAudio(const std::vector<uint8_t>& key,
                     rtc::ArrayView<const uint8_t> frame,
                     rtc::ArrayView<uint8_t> encrypted_frame,
                     size_t* bytes_written);
    
    // Selective NAL unit encryption for video (preserves structure for packetizer)
    int EncryptVideo(const std::vector<uint8_t>& key,
                     rtc::ArrayView<const uint8_t> frame,
                     rtc::ArrayView<uint8_t> encrypted_frame,
                     size_t* bytes_written);
    
    bool AesGcmEncrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t len,
                       const uint8_t* iv, size_t iv_len,
                       uint8_t* out, size_t* out_len,
                       uint8_t* tag, size_t tag_len);
    
    // Compute GMAC (authentication tag) over data
    bool ComputeGmac(const uint8_t* key, size_t key_len,
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     uint8_t* tag, size_t tag_len);
    
    // Verify GMAC
    bool VerifyGmac(const uint8_t* key, size_t key_len,
                    const uint8_t* iv, size_t iv_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* tag, size_t tag_len);
};

// Implementation of WebRTC FrameDecryptorInterface for custom decryption
// Gets keys dynamically from CustomEncryptionManager
class CustomFrameDecryptorImpl : public webrtc::FrameDecryptorInterface {
public:
    CustomFrameDecryptorImpl();
    ~CustomFrameDecryptorImpl() override = default;
    
    // RefCountInterface implementation
    void AddRef() const override { ref_count_.IncRef(); }
    rtc::RefCountReleaseStatus Release() const override {
        const auto status = ref_count_.DecRef();
        if (status == rtc::RefCountReleaseStatus::kDroppedLastRef) {
            delete this;
        }
        return status;
    }
    
    // FrameDecryptorInterface implementation
    Result Decrypt(cricket::MediaType media_type,
                   const std::vector<uint32_t>& csrcs,
                   rtc::ArrayView<const uint8_t> additional_data,
                   rtc::ArrayView<const uint8_t> encrypted_frame,
                   rtc::ArrayView<uint8_t> frame) override;
    
    size_t GetMaxPlaintextByteSize(cricket::MediaType media_type,
                                   size_t encrypted_frame_size) override;

private:
    static const uint8_t kMagicByte = 0xCE;      // Audio encryption marker
    static const uint8_t kVideoMagicByte = 0xE1; // Video encryption marker
    static const size_t kIvSize = 12;
    static const size_t kTagSize = 16;
    
    mutable webrtc::webrtc_impl::RefCounter ref_count_{0};
    int _decryptCount = 0;
    int _audioDecryptCount = 0;
    int _videoDecryptCount = 0;
    
    // Full frame decryption for audio
    Result DecryptAudio(const std::vector<std::vector<uint8_t>>& keys,
                        rtc::ArrayView<const uint8_t> encrypted_frame,
                        rtc::ArrayView<uint8_t> frame);
    
    // Selective NAL unit decryption for video
    Result DecryptVideo(const std::vector<std::vector<uint8_t>>& keys,
                        rtc::ArrayView<const uint8_t> encrypted_frame,
                        rtc::ArrayView<uint8_t> frame);
    
    bool AesGcmDecrypt(const uint8_t* key, size_t key_len,
                       const uint8_t* data, size_t len,
                       const uint8_t* iv, size_t iv_len,
                       const uint8_t* tag, size_t tag_len,
                       uint8_t* out, size_t* out_len);
    
    // Verify GMAC
    bool VerifyGmac(const uint8_t* key, size_t key_len,
                    const uint8_t* iv, size_t iv_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* tag, size_t tag_len);
};

} // namespace tgcalls

#endif // TGCALLS_CUSTOM_FRAME_ENCRYPTOR_IMPL_H
