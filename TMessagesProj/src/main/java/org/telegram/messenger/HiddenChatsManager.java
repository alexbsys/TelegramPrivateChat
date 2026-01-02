/*
 * Hidden Chats Manager for Telegram-Xalexb
 * Manages hidden chats with main and decoy password support
 * Uses AES-GCM encryption with PBKDF2 key derivation
 * 
 * Two separate lists:
 * - Main list: encrypted with main password, shown when main password entered
 * - Decoy list: encrypted with decoy password, shown when decoy password entered
 * 
 * In decoy mode, the system behaves as if decoy is the real mode, to fool anyone
 * checking the phone.
 */

package org.telegram.messenger;

import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class HiddenChatsManager {

    private static volatile HiddenChatsManager Instance = null;

    private static final String MAIN_CONFIG_FILE = "hidden_chats_config.enc";
    private static final String DECOY_CONFIG_FILE = "hidden_chats_decoy.enc";
    private static final String FILTER_CACHE_FILE = "hidden_chats_filter.enc"; // Legacy, not used
    private static final String CRC_FILTER_FILE = "chat_filter.bin"; // CRC32 filter with random padding
    private static final String MAGIC_HEADER = "THCV2";
    private static final int SALT_LENGTH = 16;
    private static final int IV_LENGTH = 12;
    private static final int PBKDF2_ITERATIONS = 10000;
    private static final int KEY_LENGTH = 256;
    private static final int MIN_CRC_ARRAY_SIZE = 64; // Minimum array size for privacy

    // Main password and list
    private String mainPasswordHash = null;
    private Set<Long> mainHiddenDialogIds = new HashSet<>();
    private String mainCachedPassword = null;
    
    // Decoy password and list
    private String decoyPasswordHash = null;
    private Set<Long> decoyHiddenDialogIds = new HashSet<>();
    private String decoyCachedPassword = null;
    
    // Combined filter set - loaded at startup for filtering WITHOUT password
    // Contains IDs from BOTH main and decoy lists
    private Set<Long> filterHiddenDialogIds = new HashSet<>();
    
    // CRC32 filter set - loaded at startup, contains CRC32 values for privacy
    // Mixed with random values to prevent analysis
    private Set<Integer> filterCrcSet = new HashSet<>();
    
    // Current mode
    private boolean isHiddenChatsMode = false;
    private boolean isDecoyMode = false;
    
    // Settings
    private static final String PREF_FORGET_PASSWORD_ON_MINIMIZE = "forget_password_on_minimize";
    private static final String PREF_ASK_PASSWORD_ON_START_MODE = "ask_password_on_start_mode";
    private static final String PREF_HAS_ENCRYPTED_CHATS = "has_encrypted_chats";
    
    // Ask password modes
    public static final int ASK_PASSWORD_DISABLED = 0;
    public static final int ASK_PASSWORD_ALWAYS = 1;
    public static final int ASK_PASSWORD_IF_ENCRYPTED_CHATS = 2;
    
    // Flag to auto-hide next created secret chat
    private boolean hideNextSecretChat = false;

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
        // Load CRC filter at startup (unencrypted, mixed with random values)
        loadCrcFilter();
        // Also try legacy filter cache for migration
        loadFilterCache();
        // Migrate from legacy to CRC filter if needed
        migrateToСrcFilter();
    }
    
    /**
     * Migrate from legacy filter to CRC filter if legacy exists but CRC doesn't
     */
    private void migrateToСrcFilter() {
        if (filterCrcSet.isEmpty() && !filterHiddenDialogIds.isEmpty()) {
            FileLog.d("HiddenChatsManager: Migrating legacy filter to CRC filter");
            // Copy legacy IDs to main list for CRC generation
            mainHiddenDialogIds.addAll(filterHiddenDialogIds);
            saveCrcFilter();
            mainHiddenDialogIds.clear();
        }
    }
    
    /**
     * Calculate CRC32 of dialog ID
     */
    private int calculateDialogCrc(long dialogId) {
        CRC32 crc = new CRC32();
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        buffer.putLong(dialogId);
        crc.update(buffer.array());
        return (int) crc.getValue();
    }
    
    /**
     * Check if dialog ID matches any CRC in the filter
     */
    public boolean isDialogInCrcFilter(long dialogId) {
        int crc = calculateDialogCrc(dialogId);
        return filterCrcSet.contains(crc);
    }
    
    private File getCrcFilterFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), CRC_FILTER_FILE);
    }
    
    /**
     * Load CRC filter at startup
     * File format: 4 bytes count + array of 4-byte CRC32 values (mixed with random)
     */
    private void loadCrcFilter() {
        try {
            File file = getCrcFilterFile();
            if (!file.exists()) {
                return;
            }
            
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            if (data.length < 4) {
                return;
            }
            
            ByteBuffer buffer = ByteBuffer.wrap(data);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            
            int count = buffer.getInt();
            if (count < 0 || count > 10000) {
                return; // Sanity check
            }
            
            // Read all CRC values (including random padding)
            while (buffer.remaining() >= 4) {
                filterCrcSet.add(buffer.getInt());
            }
            
            FileLog.d("HiddenChatsManager: Loaded CRC filter with " + filterCrcSet.size() + " entries");
        } catch (Exception e) {
            FileLog.e("HiddenChatsManager: Error loading CRC filter", e);
        }
    }
    
    /**
     * Save CRC filter with random padding for privacy
     */
    private void saveCrcFilter() {
        try {
            // Collect all hidden dialog IDs from both lists
            Set<Long> allIds = new HashSet<>();
            allIds.addAll(mainHiddenDialogIds);
            allIds.addAll(decoyHiddenDialogIds);
            
            // Also update in-memory filter
            filterHiddenDialogIds.clear();
            filterHiddenDialogIds.addAll(allIds);
            
            // Calculate CRC32 for each ID
            Set<Integer> realCrcs = new HashSet<>();
            for (Long id : allIds) {
                realCrcs.add(calculateDialogCrc(id));
            }
            
            // Determine array size (minimum MIN_CRC_ARRAY_SIZE, expand if needed)
            int arraySize = MIN_CRC_ARRAY_SIZE;
            while (realCrcs.size() > arraySize) {
                arraySize *= 2;
            }
            
            // Create array with random values
            SecureRandom random = new SecureRandom();
            int[] crcArray = new int[arraySize];
            for (int i = 0; i < arraySize; i++) {
                crcArray[i] = random.nextInt();
            }
            
            // Insert real CRCs at random positions
            int[] positions = new int[realCrcs.size()];
            Set<Integer> usedPositions = new HashSet<>();
            int idx = 0;
            for (Integer crc : realCrcs) {
                int pos;
                do {
                    pos = random.nextInt(arraySize);
                } while (usedPositions.contains(pos));
                usedPositions.add(pos);
                positions[idx++] = pos;
                crcArray[pos] = crc;
            }
            
            // Update in-memory CRC filter set
            filterCrcSet.clear();
            for (int crc : crcArray) {
                filterCrcSet.add(crc);
            }
            
            // Write to file: count + array
            ByteBuffer buffer = ByteBuffer.allocate(4 + arraySize * 4);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putInt(realCrcs.size()); // Store real count (for info only)
            for (int crc : crcArray) {
                buffer.putInt(crc);
            }
            
            File file = getCrcFilterFile();
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(buffer.array());
            fos.close();
            
            FileLog.d("HiddenChatsManager: Saved CRC filter with " + realCrcs.size() + " real + " + 
                     (arraySize - realCrcs.size()) + " random entries");
        } catch (Exception e) {
            FileLog.e("HiddenChatsManager: Error saving CRC filter", e);
        }
    }

    private File getMainConfigFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), MAIN_CONFIG_FILE);
    }
    
    private File getDecoyConfigFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), DECOY_CONFIG_FILE);
    }
    
    private File getFilterCacheFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), FILTER_CACHE_FILE);
    }
    
    /**
     * Get device key for filter cache encryption
     * This is not as secure as password, but allows filtering without user input
     */
    private String getDeviceKey() {
        try {
            String androidId = android.provider.Settings.Secure.getString(
                ApplicationLoader.applicationContext.getContentResolver(),
                android.provider.Settings.Secure.ANDROID_ID
            );
            if (androidId == null || androidId.isEmpty()) {
                androidId = "telegram_hidden_default_key";
            }
            // Add some salt to make it less predictable
            return "HiddenChatsFilter_" + androidId + "_v2";
        } catch (Exception e) {
            return "telegram_hidden_default_key_v2";
        }
    }
    
    /**
     * Load filter cache at startup - contains combined IDs from main and decoy lists
     * Encrypted with device key (not user password)
     */
    private void loadFilterCache() {
        try {
            File file = getFilterCacheFile();
            if (!file.exists()) {
                return;
            }
            
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            String decrypted = decrypt(data, getDeviceKey());
            if (decrypted == null) {
                return;
            }
            
            JSONObject json = new JSONObject(decrypted);
            JSONArray idsArray = json.optJSONArray("filter_ids");
            if (idsArray != null) {
                for (int i = 0; i < idsArray.length(); i++) {
                    filterHiddenDialogIds.add(idsArray.getLong(i));
                }
            }
            
            FileLog.d("HiddenChatsManager: Loaded filter cache with " + filterHiddenDialogIds.size() + " IDs");
        } catch (Exception e) {
            FileLog.e("HiddenChatsManager: Error loading filter cache", e);
        }
    }
    
    /**
     * Save filter cache - call after any changes to hidden chat lists
     */
    private void saveFilterCache() {
        try {
            // Combine both main and decoy lists
            Set<Long> allIds = new HashSet<>();
            allIds.addAll(mainHiddenDialogIds);
            allIds.addAll(decoyHiddenDialogIds);
            
            // Also update in-memory filter
            filterHiddenDialogIds.clear();
            filterHiddenDialogIds.addAll(allIds);
            
            JSONObject json = new JSONObject();
            JSONArray idsArray = new JSONArray();
            for (Long id : allIds) {
                idsArray.put(id);
            }
            json.put("filter_ids", idsArray);
            
            byte[] encrypted = encrypt(json.toString(), getDeviceKey());
            
            File file = getFilterCacheFile();
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(encrypted);
            fos.close();
            
            FileLog.d("HiddenChatsManager: Saved filter cache with " + allIds.size() + " IDs");
        } catch (Exception e) {
            FileLog.e("HiddenChatsManager: Error saving filter cache", e);
        }
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

    private String hashPassword(String password) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(hash, Base64.NO_WRAP);
        } catch (Exception e) {
            return password;
        }
    }

    /**
     * Try to load main config with given password
     */
    public boolean tryLoadMainConfig(String password) {
        try {
            File file = getMainConfigFile();
            if (!file.exists()) {
                return false;
            }

            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();

            String decrypted = decrypt(data, password);
            if (decrypted == null) {
                return false;
            }

            JSONObject json = new JSONObject(decrypted);
            String magic = json.optString("magic", "");
            if (!magic.equals(MAGIC_HEADER)) {
                return false;
            }

            mainHiddenDialogIds.clear();
            JSONArray hiddenChats = json.optJSONArray("hiddenChats");
            if (hiddenChats != null) {
                for (int i = 0; i < hiddenChats.length(); i++) {
                    mainHiddenDialogIds.add(hiddenChats.getLong(i));
                }
            }

            mainPasswordHash = hashPassword(password);
            mainCachedPassword = password;
            
            // Also try to load decoy config if decoy password is stored
            String storedDecoyHash = json.optString("decoyPasswordHash", null);
            if (storedDecoyHash != null && !storedDecoyHash.isEmpty()) {
                decoyPasswordHash = storedDecoyHash;
            }
            
            // Load encrypted messages manager with main password
            EncryptedMessagesManager.getInstance().loadWithPassword(password);
            EncryptedMessagesManager.getInstance().setDecoyMode(false);
            
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }
    
    /**
     * Try to load decoy config with given password
     */
    public boolean tryLoadDecoyConfig(String password) {
        try {
            File file = getDecoyConfigFile();
            if (!file.exists()) {
                return false;
            }

            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();

            String decrypted = decrypt(data, password);
            if (decrypted == null) {
                return false;
            }

            JSONObject json = new JSONObject(decrypted);
            String magic = json.optString("magic", "");
            if (!magic.equals(MAGIC_HEADER)) {
                return false;
            }

            decoyHiddenDialogIds.clear();
            JSONArray hiddenChats = json.optJSONArray("hiddenChats");
            if (hiddenChats != null) {
                for (int i = 0; i < hiddenChats.length(); i++) {
                    decoyHiddenDialogIds.add(hiddenChats.getLong(i));
                }
            }

            decoyPasswordHash = hashPassword(password);
            decoyCachedPassword = password;
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }

    private void saveMainConfig() {
        if (mainCachedPassword == null) {
            return;
        }
        
        try {
            JSONObject json = new JSONObject();
            json.put("magic", MAGIC_HEADER);
            
            JSONArray hiddenChats = new JSONArray();
            for (Long id : mainHiddenDialogIds) {
                hiddenChats.put(id);
            }
            json.put("hiddenChats", hiddenChats);
            
            // Store decoy password hash in main config
            if (decoyPasswordHash != null) {
                json.put("decoyPasswordHash", decoyPasswordHash);
            }

            byte[] encrypted = encrypt(json.toString(), mainCachedPassword);
            
            File file = getMainConfigFile();
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(encrypted);
            fos.close();
            
            // Update CRC filter for startup filtering (privacy-preserving)
            saveCrcFilter();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
    
    private void saveDecoyConfig() {
        if (decoyCachedPassword == null) {
            return;
        }
        
        try {
            JSONObject json = new JSONObject();
            json.put("magic", MAGIC_HEADER);
            
            JSONArray hiddenChats = new JSONArray();
            for (Long id : decoyHiddenDialogIds) {
                hiddenChats.put(id);
            }
            json.put("hiddenChats", hiddenChats);

            byte[] encrypted = encrypt(json.toString(), decoyCachedPassword);
            
            File file = getDecoyConfigFile();
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(encrypted);
            fos.close();
            
            // Update CRC filter for startup filtering (privacy-preserving)
            saveCrcFilter();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public boolean hasPassword() {
        return getMainConfigFile().exists() || mainPasswordHash != null;
    }

    public boolean checkMainPassword(String inputPassword) {
        if (mainPasswordHash != null) {
            return mainPasswordHash.equals(hashPassword(inputPassword));
        }
        return tryLoadMainConfig(inputPassword);
    }
    
    public boolean checkDecoyPassword(String inputPassword) {
        // First check if we have decoy password hash
        if (decoyPasswordHash != null && decoyPasswordHash.equals(hashPassword(inputPassword))) {
            // Try to load decoy config
            if (decoyCachedPassword == null) {
                tryLoadDecoyConfig(inputPassword);
            }
            return true;
        }
        // Try to load decoy config directly
        return tryLoadDecoyConfig(inputPassword);
    }
    
    /**
     * Check password and set appropriate mode
     * IMPORTANT: Check main password FIRST to avoid entering decoy mode by mistake
     */
    public boolean checkPasswordWithDecoy(String inputPassword) {
        // FIRST check main password
        if (checkMainPassword(inputPassword)) {
            isDecoyMode = false;
            // Also load decoy config if it exists (to know which chats to hide)
            if (decoyPasswordHash != null) {
                // We don't have decoy password here, but we need to load the list
                // We'll try common approach - iterate through potential passwords
                // Actually, we can't - so we need to store decoy list in main config too
                // For now, let's just try loading decoy config if password matches
            }
            return true;
        }
        // THEN check decoy password
        if (checkDecoyPassword(inputPassword)) {
            isDecoyMode = true;
            return true;
        }
        return false;
    }
    
    public boolean isDecoyMode() {
        return isDecoyMode;
    }
    
    public void resetDecoyMode() {
        isDecoyMode = false;
    }
    
    /**
     * In decoy mode - always return false (pretend decoy password is not set)
     */
    public boolean hasDecoyPassword() {
        if (isDecoyMode) {
            return false; // Always pretend not set in decoy mode
        }
        return decoyPasswordHash != null;
    }
    
    /**
     * Set decoy password - creates separate encrypted file
     * In decoy mode - do nothing (pretend it's buggy)
     */
    public void setDecoyPassword(String decoyPassword) {
        if (isDecoyMode) {
            // In decoy mode - pretend we set it but do nothing
            return;
        }
        
        if (decoyPassword == null || decoyPassword.isEmpty()) {
            decoyPasswordHash = null;
            decoyCachedPassword = null;
            getDecoyConfigFile().delete();
        } else {
            decoyPasswordHash = hashPassword(decoyPassword);
            decoyCachedPassword = decoyPassword;
            saveDecoyConfig();
        }
        saveMainConfig(); // Save decoy hash to main config
    }
    
    /**
     * Remove decoy password
     * In decoy mode - do nothing
     */
    public void removeDecoyPassword() {
        if (isDecoyMode) {
            return;
        }
        decoyPasswordHash = null;
        decoyCachedPassword = null;
        decoyHiddenDialogIds.clear();
        getDecoyConfigFile().delete();
        saveMainConfig();
    }

    /**
     * Set initial password (first time setup)
     */
    public void setPassword(String newPassword) {
        if (isDecoyMode) {
            // In decoy mode - set decoy password instead
            decoyPasswordHash = hashPassword(newPassword);
            decoyCachedPassword = newPassword;
            saveDecoyConfig();
            return;
        }
        
        mainPasswordHash = hashPassword(newPassword);
        mainCachedPassword = newPassword;
        saveMainConfig();
        
        // Initialize encrypted messages manager with this password
        EncryptedMessagesManager.getInstance().loadWithPassword(newPassword);
    }

    /**
     * Change password
     * In decoy mode - changes decoy password (but user thinks it's main)
     */
    public void changePassword(String newPassword) {
        if (isDecoyMode) {
            // Change decoy password
            decoyPasswordHash = hashPassword(newPassword);
            decoyCachedPassword = newPassword;
            saveDecoyConfig();
            return;
        }
        
        // Change main password
        mainCachedPassword = newPassword;
        mainPasswordHash = hashPassword(newPassword);
        saveMainConfig();
        
        // Re-encrypt the encrypted messages passwords file with new password
        EncryptedMessagesManager.getInstance().reEncryptWithNewPassword(newPassword);
    }

    /**
     * Add chat to hidden list
     * Adds to main or decoy list depending on current mode
     */
    public void addHiddenChat(long dialogId) {
        if (isDecoyMode) {
            decoyHiddenDialogIds.add(dialogId);
            saveDecoyConfig();
        } else {
            mainHiddenDialogIds.add(dialogId);
            saveMainConfig();
        }
    }

    /**
     * Remove chat from hidden list
     */
    public void removeHiddenChat(long dialogId) {
        if (isDecoyMode) {
            decoyHiddenDialogIds.remove(dialogId);
            saveDecoyConfig();
        } else {
            mainHiddenDialogIds.remove(dialogId);
            saveMainConfig();
        }
    }

    /**
     * Check if chat is hidden in CURRENT mode
     * For filtering search results
     */
    public boolean isHiddenInCurrentMode(long dialogId) {
        if (isDecoyMode) {
            return decoyHiddenDialogIds.contains(dialogId);
        } else {
            return mainHiddenDialogIds.contains(dialogId);
        }
    }
    
    /**
     * Check if chat is hidden in EITHER list
     * Used for filtering main chat list - should hide chats from BOTH lists
     */
    public boolean isHiddenChat(long dialogId) {
        // First check CRC filter - works even before password is entered
        // Uses CRC32 matching which is fast and privacy-preserving
        boolean inCrcFilter = isDialogInCrcFilter(dialogId);
        if (inCrcFilter) {
            FileLog.d("HiddenChatsManager: isHiddenChat(" + dialogId + ") = true (CRC filter match)");
            return true;
        }
        // Also check legacy filter cache
        if (filterHiddenDialogIds.contains(dialogId)) {
            FileLog.d("HiddenChatsManager: isHiddenChat(" + dialogId + ") = true (legacy filter)");
            return true;
        }
        // Also check in-memory lists (in case filter cache wasn't loaded yet)
        boolean inMain = mainHiddenDialogIds.contains(dialogId);
        boolean inDecoy = decoyHiddenDialogIds.contains(dialogId);
        if (inMain || inDecoy) {
            FileLog.d("HiddenChatsManager: isHiddenChat(" + dialogId + ") = true (in-memory: main=" + inMain + ", decoy=" + inDecoy + ")");
            return true;
        }
        return false;
    }
    
    /**
     * Check if chat is hidden ONLY in main list
     * Used in decoy mode to hide main chats from picker
     */
    public boolean isHiddenInMainList(long dialogId) {
        return mainHiddenDialogIds.contains(dialogId);
    }

    /**
     * Get hidden dialog IDs for CURRENT mode
     */
    public Set<Long> getHiddenDialogIds() {
        if (isDecoyMode) {
            return new HashSet<>(decoyHiddenDialogIds);
        }
        return new HashSet<>(mainHiddenDialogIds);
    }
    
    /**
     * Get ALL hidden dialog IDs (from both lists)
     * Used for filtering main chat list
     */
    public Set<Long> getAllHiddenDialogIds() {
        Set<Long> all = new HashSet<>(mainHiddenDialogIds);
        all.addAll(decoyHiddenDialogIds);
        return all;
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

    /**
     * Has hidden chats in CURRENT mode
     * Also checks CRC filter for chats hidden before password was entered
     */
    public boolean hasHiddenChats() {
        // Check CRC filter first - works even before password entered
        if (!filterCrcSet.isEmpty()) {
            return true;
        }
        // Check legacy filter
        if (!filterHiddenDialogIds.isEmpty()) {
            return true;
        }
        // Check in-memory lists
        if (isDecoyMode) {
            return !decoyHiddenDialogIds.isEmpty();
        }
        return !mainHiddenDialogIds.isEmpty();
    }
    
    /**
     * Has any hidden chats at all (for UI indication)
     */
    public boolean hasAnyHiddenChats() {
        return !filterCrcSet.isEmpty() || 
               !filterHiddenDialogIds.isEmpty() || 
               !mainHiddenDialogIds.isEmpty() || 
               !decoyHiddenDialogIds.isEmpty();
    }

    /**
     * Get hidden chats count in CURRENT mode
     */
    public int getHiddenChatsCount() {
        if (isDecoyMode) {
            return decoyHiddenDialogIds.size();
        }
        return mainHiddenDialogIds.size();
    }

    /**
     * Check if search query matches any password
     */
    public boolean isPasswordQuery(String query) {
        if (query == null || query.isEmpty()) return false;
        if (!hasPassword()) return false;
        
        // IMPORTANT: Check main password FIRST
        if (checkMainPassword(query)) {
            isDecoyMode = false;
            EncryptedMessagesManager.getInstance().setDecoyMode(false);
            return true;
        }
        // Then check decoy password
        if (checkDecoyPassword(query)) {
            isDecoyMode = true;
            EncryptedMessagesManager.getInstance().setDecoyMode(true);
            return true;
        }
        return false;
    }
    
    /**
     * Check if passwords are the same (to prevent setting identical main and decoy)
     */
    public boolean isPasswordSameAsDecoy(String password) {
        if (decoyPasswordHash == null) {
            return false;
        }
        return decoyPasswordHash.equals(hashPassword(password));
    }
    
    /**
     * Check if passwords are the same (to prevent setting identical main and decoy)
     */
    public boolean isPasswordSameAsMain(String password) {
        if (mainPasswordHash == null) {
            return false;
        }
        return mainPasswordHash.equals(hashPassword(password));
    }
    
    /**
     * For backward compatibility - load with password
     */
    public boolean tryLoadWithPassword(String password) {
        return tryLoadMainConfig(password);
    }
    
    /**
     * For backward compatibility - check password based on current mode
     */
    public boolean checkPassword(String password) {
        if (isDecoyMode) {
            return checkDecoyPassword(password);
        }
        return checkMainPassword(password);
    }
    
    /**
     * Get cached main password (for encrypted messages)
     */
    public String getMainCachedPassword() {
        return mainCachedPassword;
    }
    
    /**
     * Check if main password is loaded (needed for encrypted messages feature)
     */
    public boolean isMainPasswordLoaded() {
        return mainCachedPassword != null;
    }
    
    /**
     * Check if "forget password on minimize" setting is enabled
     * Default: false (password is remembered)
     */
    public boolean isForgetPasswordOnMinimize() {
        return ApplicationLoader.applicationContext
            .getSharedPreferences("hiddenChatsPrefs", android.content.Context.MODE_PRIVATE)
            .getBoolean(PREF_FORGET_PASSWORD_ON_MINIMIZE, false);
    }
    
    /**
     * Set "forget password on minimize" setting
     */
    public void setForgetPasswordOnMinimize(boolean forget) {
        ApplicationLoader.applicationContext
            .getSharedPreferences("hiddenChatsPrefs", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_FORGET_PASSWORD_ON_MINIMIZE, forget)
            .apply();
    }
    
    /**
     * Get ask password on start mode
     * @return ASK_PASSWORD_DISABLED, ASK_PASSWORD_ALWAYS, or ASK_PASSWORD_IF_ENCRYPTED_CHATS
     */
    public int getAskPasswordOnStartMode() {
        return ApplicationLoader.applicationContext
            .getSharedPreferences("hiddenChatsPrefs", android.content.Context.MODE_PRIVATE)
            .getInt(PREF_ASK_PASSWORD_ON_START_MODE, ASK_PASSWORD_DISABLED);
    }
    
    /**
     * Set ask password on start mode
     */
    public void setAskPasswordOnStartMode(int mode) {
        ApplicationLoader.applicationContext
            .getSharedPreferences("hiddenChatsPrefs", android.content.Context.MODE_PRIVATE)
            .edit()
            .putInt(PREF_ASK_PASSWORD_ON_START_MODE, mode)
            .apply();
    }
    
    /**
     * Check if there are any chats with encryption enabled (stored as flag)
     */
    public boolean hasEncryptedChats() {
        return ApplicationLoader.applicationContext
            .getSharedPreferences("hiddenChatsPrefs", android.content.Context.MODE_PRIVATE)
            .getBoolean(PREF_HAS_ENCRYPTED_CHATS, false);
    }
    
    /**
     * Set flag indicating there are encrypted chats
     */
    public void setHasEncryptedChats(boolean has) {
        ApplicationLoader.applicationContext
            .getSharedPreferences("hiddenChatsPrefs", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean(PREF_HAS_ENCRYPTED_CHATS, has)
            .apply();
    }
    
    /**
     * Check if password should be asked based on current mode
     */
    public boolean shouldAskPasswordOnStart() {
        int mode = getAskPasswordOnStartMode();
        if (mode == ASK_PASSWORD_DISABLED) {
            return false;
        } else if (mode == ASK_PASSWORD_ALWAYS) {
            return true;
        } else if (mode == ASK_PASSWORD_IF_ENCRYPTED_CHATS) {
            return hasEncryptedChats();
        }
        return false;
    }
    
    /**
     * Set flag to hide the next created secret chat
     */
    public void setHideNextSecretChat(boolean hide) {
        hideNextSecretChat = hide;
    }
    
    /**
     * Check and consume the hide next secret chat flag
     * @return true if the flag was set (and is now cleared)
     */
    public boolean shouldHideNextSecretChat() {
        if (hideNextSecretChat) {
            hideNextSecretChat = false;
            return true;
        }
        return false;
    }
}
