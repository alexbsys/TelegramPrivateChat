/*
 * Encrypted Calls Manager
 * Manages passwords for encrypted VoIP calls
 * 
 * - One outgoing password for encrypting outbound audio/video
 * - Multiple incoming passwords for decrypting inbound audio/video
 * - Supports AES-256 and GOST 28147 encryption
 */

package org.telegram.messenger;

import android.content.Context;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptedCallsManager {

    private static volatile EncryptedCallsManager instance;
    
    private static final String CONFIG_FILE = "encrypted_calls_config.enc";
    private static final String MAGIC_HEADER = "ENCCALL1";
    
    // Encryption types
    public static final int ENCRYPTION_AES_256 = 0;
    public static final int ENCRYPTION_GOST_28147 = 1;
    public static final int ENCRYPTION_AES_256_LITE = 2;    // Fast mode
    public static final int ENCRYPTION_GOST_28147_LITE = 3; // Fast mode
    public static final int ENCRYPTION_PASSTHROUGH = 4;     // Debug: no encryption, just trailer
    public static final int ENCRYPTION_BLOCK_XOR = 5;       // Debug: simple XOR encryption
    
    // Encryption type names for UI
    public static final String[] ENCRYPTION_NAMES = {"AES-256", "ГОСТ 28147", "AES-256 LITE", "ГОСТ LITE", "PASSTHROUGH (Debug)", "BLOCK XOR (Debug)"};
    public static final String[] ENCRYPTION_EMOJIS = {"🔒", "🔑", "⚡", "⚡", "🔓", "⊕"}; // Open lock for passthrough, XOR symbol for block xor
    
    // Default encryption type for new encryptions
    private int defaultEncryptionType = ENCRYPTION_AES_256;
    
    // Outgoing password (one) - used for encrypting our audio/video
    private String outgoingPassword = null;
    private int outgoingEncryptionType = ENCRYPTION_AES_256;
    
    // Incoming passwords (multiple) - tried for decrypting incoming audio/video
    private List<IncomingKey> incomingKeys = new ArrayList<>();
    
    // Cached derived keys for performance
    private byte[] outgoingDerivedKey = null;
    private List<byte[]> incomingDerivedKeys = new ArrayList<>();
    
    // Current call encryption status (for UI)
    private boolean outgoingEncrypted = false;
    private boolean incomingEncrypted = false;
    private boolean incomingDecryptionFailed = false;
    private int incomingDecryptedWithType = ENCRYPTION_AES_256; // Which encryption was used to decrypt
    
    public static class IncomingKey {
        public String name; // User-friendly name
        public String password;
        public boolean enabled;
        
        public IncomingKey(String name, String password) {
            this.name = name;
            this.password = password;
            this.enabled = true;
        }
        
        public JSONObject toJson() {
            try {
                JSONObject obj = new JSONObject();
                obj.put("name", name);
                obj.put("password", password);
                obj.put("enabled", enabled);
                return obj;
            } catch (Exception e) {
                return new JSONObject();
            }
        }
        
        public static IncomingKey fromJson(JSONObject obj) {
            IncomingKey key = new IncomingKey(
                obj.optString("name", ""),
                obj.optString("password", "")
            );
            key.enabled = obj.optBoolean("enabled", true);
            return key;
        }
    }
    
    public static EncryptedCallsManager getInstance() {
        if (instance == null) {
            synchronized (EncryptedCallsManager.class) {
                if (instance == null) {
                    instance = new EncryptedCallsManager();
                }
            }
        }
        return instance;
    }
    
    private EncryptedCallsManager() {
        loadConfig();
    }
    
    // ============= Encryption Type Management =============
    
    public int getDefaultEncryptionType() {
        return defaultEncryptionType;
    }
    
    public void setDefaultEncryptionType(int type) {
        if (type >= ENCRYPTION_AES_256 && type <= ENCRYPTION_BLOCK_XOR) {
            this.defaultEncryptionType = type;
            saveConfig();
        }
    }
    
    public int getOutgoingEncryptionType() {
        return outgoingEncryptionType;
    }
    
    public void setOutgoingEncryptionType(int type) {
        if (type >= ENCRYPTION_AES_256 && type <= ENCRYPTION_BLOCK_XOR) {
            this.outgoingEncryptionType = type;
            saveConfig();
        }
    }
    
    public static String getEncryptionName(int type) {
        if (type >= 0 && type < ENCRYPTION_NAMES.length) {
            return ENCRYPTION_NAMES[type];
        }
        return ENCRYPTION_NAMES[0];
    }
    
    public static String getEncryptionEmoji(int type) {
        if (type >= 0 && type < ENCRYPTION_EMOJIS.length) {
            return ENCRYPTION_EMOJIS[type];
        }
        return ENCRYPTION_EMOJIS[0];
    }
    
    // ============= Password Management =============
    
    public String getOutgoingPassword() {
        return outgoingPassword;
    }
    
    public void setOutgoingPassword(String password) {
        this.outgoingPassword = password;
        this.outgoingDerivedKey = password != null ? deriveKey(password) : null;
        saveConfig();
    }
    
    public void setOutgoingPassword(String password, int encryptionType) {
        this.outgoingPassword = password;
        this.outgoingEncryptionType = encryptionType;
        this.outgoingDerivedKey = password != null ? deriveKey(password) : null;
        saveConfig();
    }
    
    public boolean hasOutgoingPassword() {
        return outgoingPassword != null && !outgoingPassword.isEmpty();
    }
    
    // Per-call encryption toggle (for making encrypted vs unencrypted calls)
    private boolean callEncryptionEnabled = true;
    
    public void setCallEncryptionEnabled(boolean enabled) {
        this.callEncryptionEnabled = enabled;
    }
    
    public boolean isCallEncryptionEnabled() {
        return callEncryptionEnabled && hasOutgoingPassword();
    }
    
    public List<IncomingKey> getIncomingKeys() {
        return new ArrayList<>(incomingKeys);
    }
    
    public void addIncomingKey(String name, String password) {
        IncomingKey key = new IncomingKey(name, password);
        incomingKeys.add(key);
        incomingDerivedKeys.add(deriveKey(password));
        saveConfig();
    }
    
    public void removeIncomingKey(int index) {
        if (index >= 0 && index < incomingKeys.size()) {
            incomingKeys.remove(index);
            incomingDerivedKeys.remove(index);
            saveConfig();
        }
    }
    
    public void updateIncomingKey(int index, String name, String password, boolean enabled) {
        if (index >= 0 && index < incomingKeys.size()) {
            IncomingKey key = incomingKeys.get(index);
            key.name = name;
            key.password = password;
            key.enabled = enabled;
            incomingDerivedKeys.set(index, deriveKey(password));
            saveConfig();
        }
    }
    
    public void setIncomingKeyEnabled(int index, boolean enabled) {
        if (index >= 0 && index < incomingKeys.size()) {
            incomingKeys.get(index).enabled = enabled;
            saveConfig();
        }
    }
    
    // ============= Key Derivation =============
    
    /**
     * Derive a 256-bit AES key from password using PBKDF2
     */
    private byte[] deriveKey(String password) {
        try {
            // Use a fixed salt for deterministic key derivation
            // (both parties need to derive the same key from the same password)
            byte[] salt = "EncryptedCallsSalt2024".getBytes(StandardCharsets.UTF_8);
            
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 10000, 256);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            FileLog.e(e);
            // Fallback to simple SHA-256
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                return digest.digest(password.getBytes(StandardCharsets.UTF_8));
            } catch (Exception e2) {
                return new byte[32];
            }
        }
    }
    
    /**
     * Get derived key for outgoing encryption
     */
    public byte[] getOutgoingDerivedKey() {
        return outgoingDerivedKey;
    }
    
    /**
     * Get all enabled derived keys for incoming decryption attempts
     */
    public List<byte[]> getEnabledIncomingDerivedKeys() {
        List<byte[]> enabled = new ArrayList<>();
        for (int i = 0; i < incomingKeys.size(); i++) {
            if (incomingKeys.get(i).enabled) {
                enabled.add(incomingDerivedKeys.get(i));
            }
        }
        return enabled;
    }
    
    // ============= Call Status =============
    
    public void resetCallStatus() {
        outgoingEncrypted = hasOutgoingPassword();
        incomingEncrypted = false;
        incomingDecryptionFailed = false;
        incomingDecryptedWithType = ENCRYPTION_AES_256;
    }
    
    public void setIncomingDecrypted(boolean decrypted) {
        if (decrypted) {
            incomingEncrypted = true;
            incomingDecryptionFailed = false;
        } else {
            incomingDecryptionFailed = true;
        }
    }
    
    public void setIncomingDecrypted(boolean decrypted, int encryptionType) {
        setIncomingDecrypted(decrypted);
        if (decrypted) {
            incomingDecryptedWithType = encryptionType;
        }
    }
    
    public boolean isOutgoingEncrypted() {
        return outgoingEncrypted;
    }
    
    public boolean isIncomingEncrypted() {
        return incomingEncrypted;
    }
    
    public boolean isIncomingDecryptionFailed() {
        return incomingDecryptionFailed;
    }
    
    public int getIncomingDecryptedWithType() {
        return incomingDecryptedWithType;
    }
    
    /**
     * Get formatted encryption status for UI
     * @return e.g. "🔒 Зашифровано AES-256" or "🔑 Расшифровано ГОСТ 28147"
     */
    public String getOutgoingStatusText() {
        if (!outgoingEncrypted) {
            return "⚠️ " + LocaleController.getString("OutgoingUnencrypted", R.string.OutgoingUnencrypted);
        }
        return getEncryptionEmoji(outgoingEncryptionType) + " " + 
               LocaleController.getString("OutgoingEncrypted", R.string.OutgoingEncrypted) + " " +
               getEncryptionName(outgoingEncryptionType);
    }
    
    public String getIncomingStatusText() {
        if (incomingDecryptionFailed) {
            return "❌ " + LocaleController.getString("IncomingDecryptionFailed", R.string.IncomingDecryptionFailed);
        }
        if (!incomingEncrypted) {
            return "⚠️ " + LocaleController.getString("IncomingUnencrypted", R.string.IncomingUnencrypted);
        }
        return getEncryptionEmoji(incomingDecryptedWithType) + " " + 
               LocaleController.getString("IncomingDecrypted", R.string.IncomingDecrypted) + " " +
               getEncryptionName(incomingDecryptedWithType);
    }
    
    // ============= Config Persistence =============
    
    private File getConfigFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), CONFIG_FILE);
    }
    
    private void loadConfig() {
        try {
            File file = getConfigFile();
            if (!file.exists()) {
                return;
            }
            
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            // Decrypt with device key
            String jsonStr = decryptWithDeviceKey(data);
            if (jsonStr == null) {
                return;
            }
            
            JSONObject json = new JSONObject(jsonStr);
            
            // Load encryption settings
            defaultEncryptionType = json.optInt("default_encryption_type", ENCRYPTION_AES_256);
            outgoingEncryptionType = json.optInt("outgoing_encryption_type", ENCRYPTION_AES_256);
            
            outgoingPassword = json.optString("outgoing_password", null);
            if (outgoingPassword != null && outgoingPassword.isEmpty()) {
                outgoingPassword = null;
            }
            outgoingDerivedKey = outgoingPassword != null ? deriveKey(outgoingPassword) : null;
            
            incomingKeys.clear();
            incomingDerivedKeys.clear();
            JSONArray keysArray = json.optJSONArray("incoming_keys");
            if (keysArray != null) {
                for (int i = 0; i < keysArray.length(); i++) {
                    IncomingKey key = IncomingKey.fromJson(keysArray.getJSONObject(i));
                    incomingKeys.add(key);
                    incomingDerivedKeys.add(deriveKey(key.password));
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
    
    private void saveConfig() {
        try {
            JSONObject json = new JSONObject();
            json.put("default_encryption_type", defaultEncryptionType);
            json.put("outgoing_encryption_type", outgoingEncryptionType);
            json.put("outgoing_password", outgoingPassword != null ? outgoingPassword : "");
            
            JSONArray keysArray = new JSONArray();
            for (IncomingKey key : incomingKeys) {
                keysArray.put(key.toJson());
            }
            json.put("incoming_keys", keysArray);
            
            byte[] encrypted = encryptWithDeviceKey(json.toString());
            
            FileOutputStream fos = new FileOutputStream(getConfigFile());
            fos.write(encrypted);
            fos.close();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
    
    // ============= Device Key Encryption =============
    
    private byte[] getDeviceKey() {
        try {
            String androidId = android.provider.Settings.Secure.getString(
                ApplicationLoader.applicationContext.getContentResolver(),
                android.provider.Settings.Secure.ANDROID_ID
            );
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(("EncryptedCallsDeviceKey:" + androidId).getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return new byte[32];
        }
    }
    
    private byte[] encryptWithDeviceKey(String data) throws Exception {
        byte[] key = getDeviceKey();
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
        
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
        
        byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
        
        // Format: MAGIC + IV + encrypted
        byte[] result = new byte[MAGIC_HEADER.length() + iv.length + encrypted.length];
        System.arraycopy(MAGIC_HEADER.getBytes(), 0, result, 0, MAGIC_HEADER.length());
        System.arraycopy(iv, 0, result, MAGIC_HEADER.length(), iv.length);
        System.arraycopy(encrypted, 0, result, MAGIC_HEADER.length() + iv.length, encrypted.length);
        
        return result;
    }
    
    private String decryptWithDeviceKey(byte[] data) {
        try {
            if (data.length < MAGIC_HEADER.length() + 12) {
                return null;
            }
            
            String header = new String(data, 0, MAGIC_HEADER.length());
            if (!MAGIC_HEADER.equals(header)) {
                return null;
            }
            
            byte[] key = getDeviceKey();
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            
            byte[] iv = new byte[12];
            System.arraycopy(data, MAGIC_HEADER.length(), iv, 0, 12);
            
            byte[] encrypted = new byte[data.length - MAGIC_HEADER.length() - 12];
            System.arraycopy(data, MAGIC_HEADER.length() + 12, encrypted, 0, encrypted.length);
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(128, iv));
            
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }
}


