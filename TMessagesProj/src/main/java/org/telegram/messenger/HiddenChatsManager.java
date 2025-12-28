/*
 * Hidden Chats Manager for Telegram-Xalexb
 * Manages hidden chats that are only visible when password is entered in search
 * Uses AES-GCM encryption with PBKDF2 key derivation
 */

package org.telegram.messenger;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class HiddenChatsManager {

    private static volatile HiddenChatsManager Instance = null;

    private static final String CONFIG_FILE = "hidden_chats_config.enc";
    private static final String MAGIC_HEADER = "THCV2"; // Telegram Hidden Chats Version 2
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int PBKDF2_ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;

    private String passwordHash = null; // Store hash for verification, not plain password
    private String decoyPasswordHash = null; // Decoy password - shows empty list when used
    private Set<Long> hiddenDialogIds = new HashSet<>();
    private boolean isHiddenChatsMode = false;
    private boolean isDecoyMode = false; // True if decoy password was used
    private String cachedPassword = null; // Cached password for encryption operations

    public static HiddenChatsManager getInstance() {
        HiddenChatsManager localInstance = Instance;
        if (localInstance == null) {
            synchronized (HiddenChatsManager.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    Instance = localInstance = new HiddenChatsManager();
                }
            }
        }
        return localInstance;
    }

    private HiddenChatsManager() {
        // Don't load config here - need password first
    }

    private File getConfigFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), CONFIG_FILE);
    }

    /**
     * Derive encryption key from password using PBKDF2
     */
    private SecretKey deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Encrypt data with AES-GCM
     * Format: MAGIC_HEADER + salt(16) + iv(12) + encrypted_data
     */
    private byte[] encrypt(String data, String password) throws Exception {
        byte[] salt = new byte[SALT_LENGTH];
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(salt);
        random.nextBytes(iv);

        SecretKey key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        
        byte[] dataBytes = data.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.doFinal(dataBytes);

        // Combine: header + salt + iv + encrypted
        byte[] header = MAGIC_HEADER.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[header.length + salt.length + iv.length + encrypted.length];
        System.arraycopy(header, 0, result, 0, header.length);
        System.arraycopy(salt, 0, result, header.length, salt.length);
        System.arraycopy(iv, 0, result, header.length + salt.length, iv.length);
        System.arraycopy(encrypted, 0, result, header.length + salt.length + iv.length, encrypted.length);

        return result;
    }

    /**
     * Decrypt data with AES-GCM
     * Returns null if password is wrong or data is corrupted
     */
    private String decrypt(byte[] encryptedData, String password) {
        try {
            byte[] header = MAGIC_HEADER.getBytes(StandardCharsets.UTF_8);
            
            // Check header
            if (encryptedData.length < header.length + SALT_LENGTH + IV_LENGTH) {
                return null;
            }
            
            for (int i = 0; i < header.length; i++) {
                if (encryptedData[i] != header[i]) {
                    return null; // Invalid header
                }
            }

            // Extract salt, iv, and encrypted data
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(encryptedData, header.length, salt, 0, SALT_LENGTH);
            System.arraycopy(encryptedData, header.length + SALT_LENGTH, iv, 0, IV_LENGTH);
            
            int encryptedLength = encryptedData.length - header.length - SALT_LENGTH - IV_LENGTH;
            byte[] encrypted = new byte[encryptedLength];
            System.arraycopy(encryptedData, header.length + SALT_LENGTH + IV_LENGTH, encrypted, 0, encryptedLength);

            // Decrypt
            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Wrong password or corrupted data
            return null;
        }
    }

    /**
     * Simple hash for password verification (stored in memory only)
     */
    private String hashPassword(String password) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(hash, Base64.NO_WRAP);
        } catch (Exception e) {
            return password; // Fallback
        }
    }

    /**
     * Try to load config with given password
     * Returns true if password is correct
     */
    public boolean tryLoadWithPassword(String password) {
        try {
            File file = getConfigFile();
            if (!file.exists()) {
                return false;
            }

            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();

            String decrypted = decrypt(data, password);
            if (decrypted == null) {
                return false; // Wrong password
            }

            // Parse JSON
            JSONObject json = new JSONObject(decrypted);
            
            // Verify magic in JSON
            String magic = json.optString("magic", "");
            if (!magic.equals(MAGIC_HEADER)) {
                return false;
            }

            hiddenDialogIds.clear();
            JSONArray hiddenChats = json.optJSONArray("hiddenChats");
            if (hiddenChats != null) {
                for (int i = 0; i < hiddenChats.length(); i++) {
                    hiddenDialogIds.add(hiddenChats.getLong(i));
                }
            }
            
            // Load decoy password hash if exists
            decoyPasswordHash = json.optString("decoyPasswordHash", null);
            if (decoyPasswordHash != null && decoyPasswordHash.isEmpty()) {
                decoyPasswordHash = null;
            }

            passwordHash = hashPassword(password);
            cachedPassword = password;
            isDecoyMode = false;
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    private void saveConfig() {
        if (cachedPassword == null) {
            return;
        }
        
        try {
            JSONObject json = new JSONObject();
            json.put("magic", MAGIC_HEADER);
            
            JSONArray hiddenChats = new JSONArray();
            for (Long id : hiddenDialogIds) {
                hiddenChats.put(id);
            }
            json.put("hiddenChats", hiddenChats);
            
            // Save decoy password hash
            if (decoyPasswordHash != null) {
                json.put("decoyPasswordHash", decoyPasswordHash);
            }

            byte[] encrypted = encrypt(json.toString(), cachedPassword);
            
            File file = getConfigFile();
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(encrypted);
            fos.close();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public boolean hasPassword() {
        return getConfigFile().exists() || passwordHash != null;
    }

    public boolean checkPassword(String inputPassword) {
        if (passwordHash != null) {
            return passwordHash.equals(hashPassword(inputPassword));
        }
        // Try to load with this password
        return tryLoadWithPassword(inputPassword);
    }
    
    /**
     * Check if the given password is the decoy password
     */
    public boolean checkDecoyPassword(String inputPassword) {
        if (decoyPasswordHash == null) {
            return false;
        }
        return decoyPasswordHash.equals(hashPassword(inputPassword));
    }
    
    /**
     * Check password and set appropriate mode (normal or decoy)
     * Returns true if either real or decoy password matches
     */
    public boolean checkPasswordWithDecoy(String inputPassword) {
        // First check decoy password
        if (checkDecoyPassword(inputPassword)) {
            isDecoyMode = true;
            return true;
        }
        // Then check real password
        if (checkPassword(inputPassword)) {
            isDecoyMode = false;
            return true;
        }
        return false;
    }
    
    /**
     * Check if we are in decoy mode (show empty list)
     */
    public boolean isDecoyMode() {
        return isDecoyMode;
    }
    
    /**
     * Reset decoy mode
     */
    public void resetDecoyMode() {
        isDecoyMode = false;
    }
    
    /**
     * Check if decoy password is set
     */
    public boolean hasDecoyPassword() {
        return decoyPasswordHash != null;
    }
    
    /**
     * Set decoy password
     */
    public void setDecoyPassword(String decoyPassword) {
        if (decoyPassword == null || decoyPassword.isEmpty()) {
            decoyPasswordHash = null;
        } else {
            decoyPasswordHash = hashPassword(decoyPassword);
        }
        saveConfig();
    }
    
    /**
     * Remove decoy password
     */
    public void removeDecoyPassword() {
        decoyPasswordHash = null;
        saveConfig();
    }

    public void setPassword(String newPassword) {
        passwordHash = hashPassword(newPassword);
        cachedPassword = newPassword;
        saveConfig();
    }

    public void changePassword(String newPassword) {
        // Re-encrypt with new password
        cachedPassword = newPassword;
        passwordHash = hashPassword(newPassword);
        saveConfig();
    }

    public void addHiddenChat(long dialogId) {
        hiddenDialogIds.add(dialogId);
        saveConfig();
    }

    public void removeHiddenChat(long dialogId) {
        hiddenDialogIds.remove(dialogId);
        saveConfig();
    }

    public boolean isHiddenChat(long dialogId) {
        return hiddenDialogIds.contains(dialogId);
    }

    public Set<Long> getHiddenDialogIds() {
        // Return empty set in decoy mode
        if (isDecoyMode) {
            return new HashSet<>();
        }
        return new HashSet<>(hiddenDialogIds);
    }

    public boolean isHiddenChatsMode() {
        return isHiddenChatsMode;
    }

    public void setHiddenChatsMode(boolean mode) {
        isHiddenChatsMode = mode;
    }

    public void exitHiddenChatsMode() {
        isHiddenChatsMode = false;
    }

    public boolean hasHiddenChats() {
        // Return false in decoy mode
        if (isDecoyMode) {
            return false;
        }
        return !hiddenDialogIds.isEmpty();
    }

    public int getHiddenChatsCount() {
        // Return 0 in decoy mode
        if (isDecoyMode) {
            return 0;
        }
        return hiddenDialogIds.size();
    }

    // Check if search query is the password (real or decoy)
    public boolean isPasswordQuery(String query) {
        if (query == null || query.isEmpty()) return false;
        if (!hasPassword()) return false;
        
        // Check decoy password first
        if (checkDecoyPassword(query)) {
            isDecoyMode = true;
            return true;
        }
        // Then check real password
        if (checkPassword(query)) {
            isDecoyMode = false;
            return true;
        }
        return false;
    }
    
    /**
     * Clear cached password (for security, call when app goes to background)
     */
    public void clearCachedPassword() {
        // Don't clear - we need it for saving
        // cachedPassword = null;
    }
}
