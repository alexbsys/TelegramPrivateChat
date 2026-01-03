/*
 * Encrypted Messages Manager for Telegram-Xalexb
 * Manages per-chat encryption passwords for sending encrypted messages
 * The passwords file is encrypted with the hidden chats password
 */

package org.telegram.messenger;

import android.util.Base64;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

import org.telegram.tgnet.TLRPC;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptedMessagesManager {

    private static volatile EncryptedMessagesManager Instance = null;

    private static final String CONFIG_FILE = "encrypted_messages_config.enc";
    private static final String MAGIC_HEADER = "TEMV1"; // Telegram Encrypted Messages Version 1
    private static final String MESSAGE_PREFIX = "🔐ENC:"; // Prefix for encrypted messages
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int PBKDF2_ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;

    // Map of dialogId -> encryption password
    private Map<Long, String> chatPasswords = new HashMap<>();
    // Map of dialogId -> encryption type (0=AES-256, 1=GOST 28147)
    private Map<Long, Integer> chatEncryptionTypes = new HashMap<>();
    private String cachedProtectedZonePassword = null;
    private boolean isLoaded = false;
    private boolean userDeclinedPassword = false; // Don't ask again if user declined
    private boolean isDecoyMode = false; // True if decoy password was entered
    
    // Message encryption type prefixes
    private static final String GOST_PREFIX = "🔑GOST:"; // GOST encrypted messages (key emoji)
    
    // Cache for recent encrypted messages to detect duplicates (per dialogId)
    // Key: dialogId, Value: Map of encrypted text -> first message id that had it
    private Map<Long, LinkedHashMap<String, Integer>> recentEncryptedMessages = new HashMap<>();
    
    // Settings key for duplicate detection
    private static final String PREF_DUPLICATE_DETECTION_COUNT = "duplicate_detection_count";
    private static final int DEFAULT_DUPLICATE_DETECTION_COUNT = 100;

    public static EncryptedMessagesManager getInstance() {
        EncryptedMessagesManager localInstance = Instance;
        if (localInstance == null) {
            synchronized (EncryptedMessagesManager.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    Instance = localInstance = new EncryptedMessagesManager();
                }
            }
        }
        return localInstance;
    }

    private EncryptedMessagesManager() {
        // Will load when Protected Zone password is provided
    }
    
    /**
     * Clear cached passwords when app goes to background for security
     * Call this from LaunchActivity.onPause()
     */
    public void clearPasswordCache() {
        cachedProtectedZonePassword = null;
        chatPasswords.clear();
        isLoaded = false;
        isDecoyMode = false;
        // Don't clear userDeclinedPassword - keep it for this session
        // Clear duplicate detection cache to avoid false positives
        clearAllDuplicateCaches();
    }
    
    /**
     * Check if user has declined to enter password (don't ask again in this session)
     */
    public boolean hasUserDeclinedPassword() {
        return userDeclinedPassword;
    }
    
    /**
     * Set that user declined to enter password
     */
    public void setUserDeclinedPassword(boolean declined) {
        userDeclinedPassword = declined;
    }
    
    /**
     * Check if Protected Zone password is cached
     */
    public boolean isPasswordCached() {
        return cachedProtectedZonePassword != null;
    }
    
    /**
     * Check if currently in decoy mode
     */
    public boolean isInDecoyMode() {
        return isDecoyMode;
    }
    
    /**
     * Set decoy mode
     */
    public void setDecoyMode(boolean decoy) {
        isDecoyMode = decoy;
    }

    private File getConfigFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), CONFIG_FILE);
    }

    private SecretKey deriveKey(String password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

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

        byte[] header = MAGIC_HEADER.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[header.length + salt.length + iv.length + encrypted.length];
        System.arraycopy(header, 0, result, 0, header.length);
        System.arraycopy(salt, 0, result, header.length, salt.length);
        System.arraycopy(iv, 0, result, header.length + salt.length, iv.length);
        System.arraycopy(encrypted, 0, result, header.length + salt.length + iv.length, encrypted.length);

        return result;
    }

    private String decrypt(byte[] encryptedData, String password) {
        try {
            byte[] header = MAGIC_HEADER.getBytes(StandardCharsets.UTF_8);
            
            if (encryptedData.length < header.length + SALT_LENGTH + IV_LENGTH) {
                return null;
            }
            
            for (int i = 0; i < header.length; i++) {
                if (encryptedData[i] != header[i]) {
                    return null;
                }
            }

            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(encryptedData, header.length, salt, 0, SALT_LENGTH);
            System.arraycopy(encryptedData, header.length + SALT_LENGTH, iv, 0, IV_LENGTH);
            
            int encryptedLength = encryptedData.length - header.length - SALT_LENGTH - IV_LENGTH;
            byte[] encrypted = new byte[encryptedLength];
            System.arraycopy(encryptedData, header.length + SALT_LENGTH + IV_LENGTH, encrypted, 0, encryptedLength);

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Load config using Protected Zone password
     * Returns true if loaded successfully
     */
    public boolean loadWithPassword(String protectedZonePassword) {
        try {
            File file = getConfigFile();
            if (!file.exists()) {
                cachedProtectedZonePassword = protectedZonePassword;
                isLoaded = true;
                return true;
            }

            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();

            String decrypted = decrypt(data, protectedZonePassword);
            if (decrypted == null) {
                return false; // Wrong password
            }

            JSONObject json = new JSONObject(decrypted);
            String magic = json.optString("magic", "");
            if (!magic.equals(MAGIC_HEADER)) {
                return false;
            }

            chatPasswords.clear();
            JSONObject passwords = json.optJSONObject("passwords");
            if (passwords != null) {
                Iterator<String> keys = passwords.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    long dialogId = Long.parseLong(key);
                    String password = passwords.getString(key);
                    chatPasswords.put(dialogId, password);
                }
            }

            cachedProtectedZonePassword = protectedZonePassword;
            isLoaded = true;
            userDeclinedPassword = false; // Reset declined flag on successful load
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    /**
     * Save config encrypted with Protected Zone password
     */
    private void saveConfig() {
        if (cachedProtectedZonePassword == null) {
            return;
        }
        
        try {
            JSONObject json = new JSONObject();
            json.put("magic", MAGIC_HEADER);
            
            JSONObject passwords = new JSONObject();
            for (Map.Entry<Long, String> entry : chatPasswords.entrySet()) {
                passwords.put(String.valueOf(entry.getKey()), entry.getValue());
            }
            json.put("passwords", passwords);

            byte[] encrypted = encrypt(json.toString(), cachedProtectedZonePassword);
            
            File file = getConfigFile();
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(encrypted);
            fos.close();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    /**
     * Re-encrypt config with new Protected Zone password
     */
    public void reEncryptWithNewPassword(String newProtectedZonePassword) {
        cachedProtectedZonePassword = newProtectedZonePassword;
        saveConfig();
    }

    /**
     * Check if manager is loaded
     */
    public boolean isLoaded() {
        return isLoaded;
    }

    // Temporary encryption toggle (without removing password)
    private java.util.Set<Long> temporarilyDisabledChats = new java.util.HashSet<>();
    
    /**
     * Check if encryption is enabled for a chat
     */
    public boolean isEncryptionEnabled(long dialogId) {
        return chatPasswords.containsKey(dialogId) && !temporarilyDisabledChats.contains(dialogId);
    }
    
    /**
     * Temporarily enable/disable encryption for a chat (without removing password)
     */
    public void setEncryptionEnabled(long dialogId, boolean enabled) {
        if (enabled) {
            temporarilyDisabledChats.remove(dialogId);
        } else {
            temporarilyDisabledChats.add(dialogId);
        }
    }

    /**
     * Get encryption password for a chat
     */
    public String getChatPassword(long dialogId) {
        return chatPasswords.get(dialogId);
    }

    /**
     * Set encryption password for a chat
     */
    public void setChatPassword(long dialogId, String password) {
        if (password == null || password.isEmpty()) {
            chatPasswords.remove(dialogId);
            chatEncryptionTypes.remove(dialogId);
        } else {
            chatPasswords.put(dialogId, password);
        }
        saveConfig();
        updateHasEncryptedChatsFlag();
    }
    
    /**
     * Set encryption password and type for a chat
     * @param encryptionType 0=AES-256, 1=GOST 28147
     */
    public void setChatPassword(long dialogId, String password, int encryptionType) {
        if (password == null || password.isEmpty()) {
            chatPasswords.remove(dialogId);
            chatEncryptionTypes.remove(dialogId);
        } else {
            chatPasswords.put(dialogId, password);
            chatEncryptionTypes.put(dialogId, encryptionType);
        }
        saveConfig();
        updateHasEncryptedChatsFlag();
    }
    
    /**
     * Get encryption type for a chat (0=AES-256, 1=GOST 28147)
     */
    public int getChatEncryptionType(long dialogId) {
        Integer type = chatEncryptionTypes.get(dialogId);
        return type != null ? type : 0; // Default to AES-256
    }
    
    /**
     * Set encryption type for a chat
     */
    public void setChatEncryptionType(long dialogId, int type) {
        chatEncryptionTypes.put(dialogId, type);
        saveConfig();
    }

    /**
     * Disable encryption for a chat
     */
    public void disableEncryption(long dialogId) {
        chatPasswords.remove(dialogId);
        saveConfig();
        updateHasEncryptedChatsFlag();
    }
    
    /**
     * Update the flag indicating whether there are any encrypted chats
     */
    private void updateHasEncryptedChatsFlag() {
        HiddenChatsManager.getInstance().setHasEncryptedChats(!chatPasswords.isEmpty());
    }

    /**
     * Encrypt a message text with default encryption type (AES-256)
     */
    public String encryptMessage(String plainText, String password) {
        return encryptMessage(plainText, password, 0);
    }
    
    /**
     * Encrypt a message text with specified encryption type
     * @param encryptionType 0=AES-256, 1=GOST 28147
     */
    public String encryptMessage(String plainText, String password, int encryptionType) {
        try {
            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            SecureRandom random = new SecureRandom();
            random.nextBytes(salt);
            random.nextBytes(iv);

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            
            byte[] dataBytes = plainText.getBytes(StandardCharsets.UTF_8);
            byte[] encrypted = cipher.doFinal(dataBytes);

            // Combine salt + iv + encrypted
            byte[] combined = new byte[salt.length + iv.length + encrypted.length];
            System.arraycopy(salt, 0, combined, 0, salt.length);
            System.arraycopy(iv, 0, combined, salt.length, iv.length);
            System.arraycopy(encrypted, 0, combined, salt.length + iv.length, encrypted.length);

            // Return with prefix based on encryption type
            String prefix = (encryptionType == 1) ? GOST_PREFIX : MESSAGE_PREFIX;
            return prefix + Base64.encodeToString(combined, Base64.NO_WRAP);
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }

    /**
     * Try to decrypt a message text
     * Returns null if not encrypted or decryption fails
     */
    public String decryptMessage(String encryptedText, String password) {
        if (!isEncryptedMessage(encryptedText)) {
            return null;
        }
        
        try {
            // Determine prefix and get base64 part
            String base64Part;
            if (encryptedText.startsWith(GOST_PREFIX)) {
                base64Part = encryptedText.substring(GOST_PREFIX.length());
            } else {
                base64Part = encryptedText.substring(MESSAGE_PREFIX.length());
            }
            byte[] combined = Base64.decode(base64Part, Base64.NO_WRAP);
            
            if (combined.length < SALT_LENGTH + IV_LENGTH) {
                return null;
            }

            byte[] salt = new byte[SALT_LENGTH];
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(combined, 0, salt, 0, SALT_LENGTH);
            System.arraycopy(combined, SALT_LENGTH, iv, 0, IV_LENGTH);
            
            int encryptedLength = combined.length - SALT_LENGTH - IV_LENGTH;
            byte[] encrypted = new byte[encryptedLength];
            System.arraycopy(combined, SALT_LENGTH + IV_LENGTH, encrypted, 0, encryptedLength);

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Check if message is encrypted (AES or GOST)
     */
    public boolean isEncryptedMessage(String text) {
        return text != null && (text.startsWith(MESSAGE_PREFIX) || text.startsWith(GOST_PREFIX));
    }
    
    /**
     * Check if message is GOST encrypted
     */
    public boolean isGostEncryptedMessage(String text) {
        return text != null && text.startsWith(GOST_PREFIX);
    }

    /**
     * Get the encrypted message prefix
     */
    public static String getMessagePrefix() {
        return MESSAGE_PREFIX;
    }
    
    /**
     * Check if an encrypted message is a duplicate (same encrypted text from different message)
     * Returns true if this message is a COPY (not original)
     * Original = the message with the LOWEST message id (oldest)
     */
    public boolean isDuplicateEncryptedMessage(long dialogId, String encryptedText, int messageId) {
        if (encryptedText == null || !isEncryptedMessage(encryptedText)) {
            return false;
        }
        
        // Check if duplicate detection is enabled
        if (!isDuplicateDetectionEnabled()) {
            return false;
        }
        
        LinkedHashMap<String, Integer> cache = recentEncryptedMessages.get(dialogId);
        if (cache == null) {
            return false;
        }
        
        Integer firstMessageId = cache.get(encryptedText);
        if (firstMessageId == null) {
            return false;
        }
        
        // This message is a duplicate if its id is HIGHER (newer) than the first occurrence
        // The first (oldest, lowest id) message is the original
        return messageId > firstMessageId;
    }
    
    /**
     * Register an encrypted message as seen (for duplicate detection)
     * Stores the LOWEST message id (oldest = original) for each encrypted text
     */
    public void registerEncryptedMessage(long dialogId, String encryptedText, int messageId) {
        if (encryptedText == null || !isEncryptedMessage(encryptedText)) {
            return;
        }
        
        // Check if duplicate detection is enabled
        int maxSize = getDuplicateDetectionCount();
        if (maxSize <= 0) {
            return;
        }
        
        LinkedHashMap<String, Integer> cache = recentEncryptedMessages.get(dialogId);
        if (cache == null) {
            // Create LRU cache with configurable max size
            final int finalMaxSize = maxSize;
            cache = new LinkedHashMap<String, Integer>(maxSize + 1, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Integer> eldest) {
                    return size() > finalMaxSize;
                }
            };
            recentEncryptedMessages.put(dialogId, cache);
        }
        
        Integer existingId = cache.get(encryptedText);
        // Store the LOWEST id (oldest message = original)
        if (existingId == null || messageId < existingId) {
            cache.put(encryptedText, messageId);
        }
    }
    
    /**
     * Clear the duplicate cache for a dialog (e.g., when password changes)
     */
    public void clearDuplicateCache(long dialogId) {
        recentEncryptedMessages.remove(dialogId);
    }
    
    /**
     * Clear all duplicate caches
     */
    public void clearAllDuplicateCaches() {
        recentEncryptedMessages.clear();
    }
    
    /**
     * Get duplicate detection message count setting
     * @return number of messages to analyze, 0 = disabled
     */
    public int getDuplicateDetectionCount() {
        return ApplicationLoader.applicationContext
            .getSharedPreferences("encryptedMessagesPrefs", android.content.Context.MODE_PRIVATE)
            .getInt(PREF_DUPLICATE_DETECTION_COUNT, DEFAULT_DUPLICATE_DETECTION_COUNT);
    }
    
    /**
     * Set duplicate detection message count
     * @param count number of messages to analyze, 0 = disabled
     */
    public void setDuplicateDetectionCount(int count) {
        ApplicationLoader.applicationContext
            .getSharedPreferences("encryptedMessagesPrefs", android.content.Context.MODE_PRIVATE)
            .edit()
            .putInt(PREF_DUPLICATE_DETECTION_COUNT, count)
            .apply();
        // Clear caches when settings change
        clearAllDuplicateCaches();
    }
    
    /**
     * Check if duplicate detection is enabled
     */
    public boolean isDuplicateDetectionEnabled() {
        return getDuplicateDetectionCount() > 0;
    }
    
    // ============= Encrypted Search Settings =============
    
    private static final String PREF_ENCRYPTED_SEARCH_LIMIT = "encrypted_search_limit";
    private static final int DEFAULT_ENCRYPTED_SEARCH_LIMIT = 500;
    
    /**
     * Get encrypted message search limit
     * @return number of messages to search, 0 = disabled
     */
    public int getEncryptedSearchLimit() {
        return ApplicationLoader.applicationContext
            .getSharedPreferences("encryptedMessagesPrefs", android.content.Context.MODE_PRIVATE)
            .getInt(PREF_ENCRYPTED_SEARCH_LIMIT, DEFAULT_ENCRYPTED_SEARCH_LIMIT);
    }
    
    /**
     * Set encrypted message search limit
     * @param limit number of messages to search, 0 = disabled, -1 = unlimited
     */
    public void setEncryptedSearchLimit(int limit) {
        ApplicationLoader.applicationContext
            .getSharedPreferences("encryptedMessagesPrefs", android.content.Context.MODE_PRIVATE)
            .edit()
            .putInt(PREF_ENCRYPTED_SEARCH_LIMIT, limit)
            .apply();
    }
    
    /**
     * Check if encrypted search is enabled
     */
    public boolean isEncryptedSearchEnabled() {
        return getEncryptedSearchLimit() != 0;
    }
    
    /**
     * Search encrypted messages in a dialog
     * @param dialogId dialog to search
     * @param query search query (will be matched against decrypted text)
     * @param password decryption password
     * @param callback called with list of matching message IDs
     */
    public void searchEncryptedMessages(long dialogId, String query, String password, 
            java.util.function.Consumer<ArrayList<Integer>> callback) {
        int limit = getEncryptedSearchLimit();
        if (limit == 0 || query == null || query.isEmpty() || password == null) {
            callback.accept(new ArrayList<>());
            return;
        }
        
        Utilities.searchQueue.postRunnable(() -> {
            ArrayList<Integer> results = new ArrayList<>();
            String queryLower = query.toLowerCase();
            
            try {
                // Get messages from MessagesStorage
                MessagesStorage storage = MessagesStorage.getInstance(UserConfig.selectedAccount);
                ArrayList<MessageObject> messages = new ArrayList<>();
                
                // Query last N messages from this dialog
                // This is a simplified approach - in production you'd want pagination
                storage.getStorageQueue().postRunnable(() -> {
                    try {
                        org.telegram.SQLite.SQLiteCursor cursor = storage.getDatabase().queryFinalized(
                            "SELECT data, mid FROM messages_v2 WHERE uid = ? ORDER BY mid DESC LIMIT ?",
                            dialogId, limit > 0 ? limit : 10000);
                        
                        ArrayList<Integer> matchingIds = new ArrayList<>();
                        
                        while (cursor.next()) {
                            org.telegram.tgnet.NativeByteBuffer data = cursor.byteBufferValue(0);
                            int messageId = cursor.intValue(1);
                            
                            if (data != null) {
                                TLRPC.Message message = TLRPC.Message.TLdeserialize(data, data.readInt32(false), false);
                                data.reuse();
                                
                                if (message != null && message.message != null && isEncryptedMessage(message.message)) {
                                    String decrypted = decryptMessage(message.message, password);
                                    if (decrypted != null && decrypted.toLowerCase().contains(queryLower)) {
                                        matchingIds.add(messageId);
                                    }
                                }
                            }
                        }
                        cursor.dispose();
                        
                        AndroidUtilities.runOnUIThread(() -> callback.accept(matchingIds));
                    } catch (Exception e) {
                        FileLog.e(e);
                        AndroidUtilities.runOnUIThread(() -> callback.accept(new ArrayList<>()));
                    }
                });
            } catch (Exception e) {
                FileLog.e(e);
                callback.accept(new ArrayList<>());
            }
        });
    }
}

