/*
 * Encrypted Calls Manager
 * Manages passwords for encrypted VoIP calls
 * 
 * - One outgoing password for encrypting outbound audio/video
 * - Multiple incoming passwords for decrypting inbound audio/video
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
    
    // Outgoing password (one) - used for encrypting our audio/video
    private String outgoingPassword = null;
    
    // Incoming passwords (multiple) - tried for decrypting incoming audio/video
    private List<IncomingKey> incomingKeys = new ArrayList<>();
    
    // Cached derived keys for performance
    private byte[] outgoingDerivedKey = null;
    private List<byte[]> incomingDerivedKeys = new ArrayList<>();
    
    // Current call encryption status (for UI)
    private boolean outgoingEncrypted = false;
    private boolean incomingEncrypted = false;
    private boolean incomingDecryptionFailed = false;
    
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
    
    // ============= Password Management =============
    
    public String getOutgoingPassword() {
        return outgoingPassword;
    }
    
    public void setOutgoingPassword(String password) {
        this.outgoingPassword = password;
        this.outgoingDerivedKey = password != null ? deriveKey(password) : null;
        saveConfig();
    }
    
    public boolean hasOutgoingPassword() {
        return outgoingPassword != null && !outgoingPassword.isEmpty();
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
    }
    
    public void setIncomingDecrypted(boolean decrypted) {
        if (decrypted) {
            incomingEncrypted = true;
            incomingDecryptionFailed = false;
        } else {
            incomingDecryptionFailed = true;
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


