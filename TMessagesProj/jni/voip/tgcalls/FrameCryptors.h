#ifndef TGCALLS_FRAME_CRYPTORS_H
#define TGCALLS_FRAME_CRYPTORS_H

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>
#include <map>
#include <openssl/evp.h>

namespace tgcalls {

// SEI-based encryption: trailer goes in separate SEI NAL, not inside encrypted NAL
// This preserves NAL structure for RTP packetization

// Custom UUID for our SEI messages (16 bytes)
static constexpr uint8_t kSeiUuid[16] = {
    0xC1, 0x9E, 0x6C, 0x8F, 0x24, 0x5A, 0x4B, 0x7D,
    0x8E, 0x3F, 0x2A, 0x1B, 0x0C, 0x4D, 0x5E, 0x6F
};

// Pending SEI trailer info (stored when SEI arrives before its NAL)
struct PendingSeiInfo {
    uint8_t magic;
    uint32_t seqNum;
    std::vector<uint8_t> iv;      // For AES
    std::vector<uint8_t> tag;     // For AES
    uint32_t checksum;            // For XOR/Passthrough
};

// Result of encryption/decryption
struct CryptResult {
    bool success;
    size_t bytesWritten;
    int keyIndex;  // Which key was used for decryption (-1 if failed)
    
    CryptResult(bool s, size_t bytes, int idx = -1) 
        : success(s), bytesWritten(bytes), keyIndex(idx) {}
    
    static CryptResult Ok(size_t bytes, int keyIdx = 0) { 
        return CryptResult(true, bytes, keyIdx); 
    }
    static CryptResult Failed() { 
        return CryptResult(false, 0, -1); 
    }
};

// ==================== Base Interfaces ====================

class IFrameEncryptor {
public:
    virtual ~IFrameEncryptor() = default;
    
    // Set the key to use for encryption
    virtual void SetKey(const std::vector<uint8_t>& key) = 0;
    virtual bool HasKey() const = 0;
    
    // Encrypt audio frame (full frame encryption)
    virtual CryptResult EncryptAudio(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) = 0;
    
    // Encrypt video frame (NAL-preserving encryption)
    virtual CryptResult EncryptVideo(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) = 0;
    
    // Get max ciphertext sizes
    virtual size_t GetMaxAudioCiphertextSize(size_t plaintextSize) const = 0;
    virtual size_t GetMaxVideoCiphertextSize(size_t plaintextSize) const = 0;
    
    // Get encryption type ID (0=AES, 1=GOST, 2=AES_LITE, 3=GOST_LITE)
    virtual int GetEncryptionTypeId() const = 0;
};

class IFrameDecryptor {
public:
    virtual ~IFrameDecryptor() = default;
    
    // Try to find a working key from the list for audio
    virtual int TryFindAudioKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) = 0;
    
    // Try to find a working key from the list for video
    virtual int TryFindVideoKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) = 0;
    
    // Set the key to use for decryption
    virtual void SetKey(const std::vector<uint8_t>& key) = 0;
    virtual bool HasKey() const = 0;
    
    // Decrypt audio frame
    virtual CryptResult DecryptAudio(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) = 0;
    
    // Decrypt video frame (NAL-preserving)
    virtual CryptResult DecryptVideo(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) = 0;
    
    // Get encryption type ID (for reporting)
    virtual int GetEncryptionTypeId() const = 0;
    
    // Get magic bytes for detection
    virtual uint8_t GetAudioMagicByte() const = 0;
    virtual uint8_t GetVideoMagicByte() const = 0;
};

// ==================== AES-256-GCM ====================

class Aes256Cryptor : public IFrameEncryptor, public IFrameDecryptor {
public:
    Aes256Cryptor();
    ~Aes256Cryptor() override;
    
    // IFrameEncryptor
    void SetKey(const std::vector<uint8_t>& key) override;
    bool HasKey() const override { return !_key.empty(); }
    
    CryptResult EncryptAudio(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    CryptResult EncryptVideo(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    size_t GetMaxAudioCiphertextSize(size_t plaintextSize) const override;
    size_t GetMaxVideoCiphertextSize(size_t plaintextSize) const override;
    int GetEncryptionTypeId() const override { return 0; }
    
    // IFrameDecryptor
    int TryFindAudioKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    int TryFindVideoKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    CryptResult DecryptAudio(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    CryptResult DecryptVideo(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    uint8_t GetAudioMagicByte() const override { return kAudioMagic; }
    uint8_t GetVideoMagicByte() const override { return kVideoMagic; }
    
    static constexpr uint8_t kAudioMagic = 0xCE;
    static constexpr uint8_t kVideoMagic = 0xE1;
    static constexpr size_t kIvSize = 12;
    static constexpr size_t kTagSize = 16;
    // SEI trailer: [UUID 16B][SEQ_NUM 4B][MAGIC 1B][IV 12B][TAG 16B]
    static constexpr size_t kSeiPayloadSize = 16 + 4 + 1 + kIvSize + kTagSize;
    
private:
    EVP_CIPHER_CTX* _ctx;
    std::vector<uint8_t> _key;
    uint32_t _seqNum = 0;
    std::map<uint32_t, PendingSeiInfo> _pendingSeis;
    
    bool ComputeGmac(const uint8_t* iv, const uint8_t* aad, size_t aad_len, uint8_t* tag);
    bool VerifyGmac(const uint8_t* iv, const uint8_t* aad, size_t aad_len, const uint8_t* tag);
    size_t WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum, 
                       const uint8_t* iv, const uint8_t* tag, bool isH265);
    bool ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info);
    
    // AES-CTR for in-place encryption (no size change)
    bool EncryptCtr(const uint8_t* plaintext, uint8_t* ciphertext, size_t size, const uint8_t* iv);
    bool DecryptCtr(const uint8_t* ciphertext, uint8_t* plaintext, size_t size, const uint8_t* iv);
};

// ==================== GOST 28147-89 ====================

class Gost28147Cryptor : public IFrameEncryptor, public IFrameDecryptor {
public:
    Gost28147Cryptor();
    ~Gost28147Cryptor() override;
    
    // IFrameEncryptor
    void SetKey(const std::vector<uint8_t>& key) override;
    bool HasKey() const override { return !_key.empty(); }
    
    CryptResult EncryptAudio(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    CryptResult EncryptVideo(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    size_t GetMaxAudioCiphertextSize(size_t plaintextSize) const override;
    size_t GetMaxVideoCiphertextSize(size_t plaintextSize) const override;
    int GetEncryptionTypeId() const override { return 1; }
    
    // IFrameDecryptor
    int TryFindAudioKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    int TryFindVideoKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    CryptResult DecryptAudio(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    CryptResult DecryptVideo(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    uint8_t GetAudioMagicByte() const override { return kAudioMagic; }
    uint8_t GetVideoMagicByte() const override { return kVideoMagic; }
    
    static constexpr uint8_t kAudioMagic = 0xD1;
    static constexpr uint8_t kVideoMagic = 0xD2;
    static constexpr size_t kNonceSize = 8;
    static constexpr size_t kChecksumSize = 4;
    static constexpr size_t kSeiPayloadSize = 16 + 4 + 1 + kNonceSize + kChecksumSize;
    
private:
    std::vector<uint8_t> _key;
    
    struct PendingSeiInfo {
        uint32_t seqNum;
        uint8_t magic;
        uint8_t nonce[8];
        uint32_t checksum;
    };
    
    std::map<uint32_t, PendingSeiInfo> _pendingSeis;
    uint32_t _videoSeqNum = 0;
    
    size_t WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum,
                       const uint8_t* nonce, uint32_t checksum, bool isH265);
    bool ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info);
};

// ==================== AES-256 LITE ====================

class Aes256LiteCryptor : public IFrameEncryptor, public IFrameDecryptor {
public:
    Aes256LiteCryptor();
    ~Aes256LiteCryptor() override;
    
    // IFrameEncryptor
    void SetKey(const std::vector<uint8_t>& key) override;
    bool HasKey() const override { return !_key.empty(); }
    
    CryptResult EncryptAudio(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    CryptResult EncryptVideo(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    size_t GetMaxAudioCiphertextSize(size_t plaintextSize) const override;
    size_t GetMaxVideoCiphertextSize(size_t plaintextSize) const override;
    int GetEncryptionTypeId() const override { return 2; }
    
    // IFrameDecryptor
    int TryFindAudioKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    int TryFindVideoKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    CryptResult DecryptAudio(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    CryptResult DecryptVideo(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    uint8_t GetAudioMagicByte() const override { return kAudioMagic; }
    uint8_t GetVideoMagicByte() const override { return kVideoMagic; }
    
    static constexpr uint8_t kAudioMagic = 0xA1;
    static constexpr uint8_t kVideoMagic = 0xA2;
    static constexpr size_t kIvSize = 12;
    static constexpr size_t kTagSize = 16;
    static constexpr size_t kEncryptedHeadSize = 64;
    static constexpr size_t kXorKeySize = 4;
    static constexpr size_t kSeiPayloadSize = 16 + 4 + 1 + kIvSize + kTagSize;
    
private:
    EVP_CIPHER_CTX* _ctx;
    std::vector<uint8_t> _key;
    
    struct PendingSeiInfo {
        uint32_t seqNum;
        uint8_t magic;
        std::vector<uint8_t> iv;
        std::vector<uint8_t> tag;
    };
    
    std::map<uint32_t, PendingSeiInfo> _pendingSeis;
    uint32_t _videoSeqNum = 0;
    
    size_t WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum,
                       const uint8_t* iv, const uint8_t* tag, bool isH265);
    bool ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info);
};

// ==================== GOST LITE ====================

class GostLiteCryptor : public IFrameEncryptor, public IFrameDecryptor {
public:
    GostLiteCryptor();
    ~GostLiteCryptor() override;
    
    // IFrameEncryptor
    void SetKey(const std::vector<uint8_t>& key) override;
    bool HasKey() const override { return !_key.empty(); }
    
    CryptResult EncryptAudio(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    CryptResult EncryptVideo(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    size_t GetMaxAudioCiphertextSize(size_t plaintextSize) const override;
    size_t GetMaxVideoCiphertextSize(size_t plaintextSize) const override;
    int GetEncryptionTypeId() const override { return 3; }
    
    // IFrameDecryptor
    int TryFindAudioKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    int TryFindVideoKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    CryptResult DecryptAudio(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    CryptResult DecryptVideo(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    uint8_t GetAudioMagicByte() const override { return kAudioMagic; }
    uint8_t GetVideoMagicByte() const override { return kVideoMagic; }
    
    static constexpr uint8_t kAudioMagic = 0xB1;
    static constexpr uint8_t kVideoMagic = 0xB2;
    static constexpr size_t kNonceSize = 8;
    static constexpr size_t kChecksumSize = 4;
    static constexpr size_t kEncryptedHeadSize = 64;
    static constexpr size_t kXorKeySize = 4;
    static constexpr size_t kSeiPayloadSize = 16 + 4 + 1 + kNonceSize + kChecksumSize;
    
private:
    std::vector<uint8_t> _key;
    
    struct PendingSeiInfo {
        uint32_t seqNum;
        uint8_t magic;
        uint8_t nonce[8];
        uint32_t checksum;
    };
    
    std::map<uint32_t, PendingSeiInfo> _pendingSeis;
    uint32_t _videoSeqNum = 0;
    
    size_t WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum,
                       const uint8_t* nonce, uint32_t checksum, bool isH265);
    bool ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info);
};

// ==================== PASSTHROUGH (Debug - no encryption) ====================
// Simply adds a trailer without modifying the payload
// Used to test if packet structure/RTP is the issue

class PassthroughCryptor : public IFrameEncryptor, public IFrameDecryptor {
public:
    PassthroughCryptor();
    ~PassthroughCryptor() override;
    
    // IFrameEncryptor
    void SetKey(const std::vector<uint8_t>& key) override;
    bool HasKey() const override { return true; }  // Always "has key"
    
    CryptResult EncryptAudio(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    CryptResult EncryptVideo(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    size_t GetMaxAudioCiphertextSize(size_t plaintextSize) const override;
    size_t GetMaxVideoCiphertextSize(size_t plaintextSize) const override;
    int GetEncryptionTypeId() const override { return 4; }
    
    // IFrameDecryptor
    int TryFindAudioKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    int TryFindVideoKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    CryptResult DecryptAudio(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    CryptResult DecryptVideo(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    uint8_t GetAudioMagicByte() const override { return kAudioMagic; }
    uint8_t GetVideoMagicByte() const override { return kVideoMagic; }
    
    // SEI trailer format: [UUID 16B][SEQ_NUM 4B][MAGIC 1B][CHECKSUM 4B]
    static constexpr uint8_t kAudioMagic = 0xF0;
    static constexpr uint8_t kVideoMagic = 0xF1;
    static constexpr size_t kChecksumSize = 4;
    static constexpr size_t kSeiPayloadSize = 16 + 4 + 1 + 4;  // UUID + seq + magic + checksum
    
private:
    std::vector<uint8_t> _key;
    uint32_t _seqNum = 0;
    std::map<uint32_t, PendingSeiInfo> _pendingSeis;
    
    uint32_t ComputeChecksum(const uint8_t* data, size_t size);
    size_t WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum, uint32_t checksum, bool isH265);
    bool ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info);
};

// ==================== BLOCK XOR (Debug - simple XOR encryption) ====================
// XOR encryption with key, block-based, with checksum in trailer
// Used to test if encrypting payload causes issues

class BlockXorCryptor : public IFrameEncryptor, public IFrameDecryptor {
public:
    BlockXorCryptor();
    ~BlockXorCryptor() override;
    
    // IFrameEncryptor
    void SetKey(const std::vector<uint8_t>& key) override;
    bool HasKey() const override { return !_key.empty(); }
    
    CryptResult EncryptAudio(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    CryptResult EncryptVideo(
        const uint8_t* plaintext, size_t plaintextSize,
        uint8_t* ciphertext, size_t ciphertextMaxSize) override;
    
    size_t GetMaxAudioCiphertextSize(size_t plaintextSize) const override;
    size_t GetMaxVideoCiphertextSize(size_t plaintextSize) const override;
    int GetEncryptionTypeId() const override { return 5; }
    
    // IFrameDecryptor
    int TryFindAudioKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    int TryFindVideoKey(
        const std::vector<std::vector<uint8_t>>& keys,
        const uint8_t* ciphertext, size_t ciphertextSize) override;
    
    CryptResult DecryptAudio(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    CryptResult DecryptVideo(
        const uint8_t* ciphertext, size_t ciphertextSize,
        uint8_t* plaintext, size_t plaintextMaxSize) override;
    
    uint8_t GetAudioMagicByte() const override { return kAudioMagic; }
    uint8_t GetVideoMagicByte() const override { return kVideoMagic; }
    
    // SEI trailer format: [UUID 16B][SEQ_NUM 4B][MAGIC 1B][CHECKSUM 4B]
    static constexpr uint8_t kAudioMagic = 0xF2;
    static constexpr uint8_t kVideoMagic = 0xF3;
    static constexpr size_t kChecksumSize = 4;
    static constexpr size_t kSeiPayloadSize = 16 + 4 + 1 + 4;  // UUID + seq + magic + checksum
    
private:
    std::vector<uint8_t> _key;
    uint32_t _seqNum = 0;
    std::map<uint32_t, PendingSeiInfo> _pendingSeis;
    
    void XorData(const uint8_t* input, uint8_t* output, size_t size);
    uint32_t ComputeChecksum(const uint8_t* data, size_t size);
    size_t WriteSeiNal(uint8_t* output, size_t maxSize, uint32_t seqNum, uint32_t checksum, bool isH265);
    bool ParseSeiNal(const uint8_t* data, size_t size, PendingSeiInfo& info);
};

// ==================== Factory ====================

class CryptorFactory {
public:
    // Create encryptor by type ID:
    // 0=AES, 1=GOST, 2=AES_LITE, 3=GOST_LITE, 4=PASSTHROUGH, 5=BLOCK_XOR
    static std::unique_ptr<IFrameEncryptor> CreateEncryptor(int type);
    
    // Create decryptor by audio magic byte
    static std::unique_ptr<IFrameDecryptor> CreateDecryptorByAudioMagic(uint8_t magicByte);
    
    // Create decryptor by video magic byte
    static std::unique_ptr<IFrameDecryptor> CreateDecryptorByVideoMagic(uint8_t magicByte);
    
    // Check if magic byte is known audio magic
    static bool IsKnownAudioMagic(uint8_t magic);
    
    // Check if magic byte is known video magic
    static bool IsKnownVideoMagic(uint8_t magic);
};

} // namespace tgcalls

#endif // TGCALLS_FRAME_CRYPTORS_H
