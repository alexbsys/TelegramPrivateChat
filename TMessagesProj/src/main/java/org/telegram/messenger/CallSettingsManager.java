/*
 * Custom call settings manager for TURN servers and WebRTC configuration
 */

package org.telegram.messenger;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

public class CallSettingsManager {

    private static volatile CallSettingsManager instance;
    
    private static final String CONFIG_FILE = "call_settings.json";
    
    // Settings
    private boolean forceWebRTC = false;
    private boolean useTCP = false;
    private boolean replaceStandardServers = false; // If true, only use custom TURN servers
    private boolean disableP2P = false; // If true, force relay-only mode (no direct P2P connections)
    private List<TurnServer> customTurnServers = new ArrayList<>();
    
    // Call server mode
    private boolean useCallServer = false; // If true, fetch TURN servers from call server instead of manual
    private String callServerUrl = ""; // URL of the call manager server
    
    // Video codec preference
    public static final int VIDEO_CODEC_AUTO = 0;
    public static final int VIDEO_CODEC_H264 = 1;
    public static final int VIDEO_CODEC_H265 = 2;
    private int preferredVideoCodec = VIDEO_CODEC_AUTO;
    
    // Debug info overlay
    private boolean showDebugInfo = false;
    
    // Call control lists
    private List<Long> blacklist = new ArrayList<>(); // User IDs to auto-reject
    private boolean whitelistEnabled = false;
    private List<Long> whitelist = new ArrayList<>(); // If enabled, only accept calls from these users
    private List<AutoAnswerEntry> autoAnswerList = new ArrayList<>(); // Auto-answer settings per user
    
    public static final int AUTO_ANSWER_AUDIO_ONLY = 0;
    public static final int AUTO_ANSWER_AUDIO_VIDEO = 1;
    
    public static class AutoAnswerEntry {
        public long userId;
        public int mode; // AUTO_ANSWER_AUDIO_ONLY or AUTO_ANSWER_AUDIO_VIDEO
        
        public AutoAnswerEntry() {}
        
        public AutoAnswerEntry(long userId, int mode) {
            this.userId = userId;
            this.mode = mode;
        }
        
        public JSONObject toJson() {
            try {
                JSONObject obj = new JSONObject();
                obj.put("user_id", userId);
                obj.put("mode", mode);
                return obj;
            } catch (Exception e) {
                return new JSONObject();
            }
        }
        
        public static AutoAnswerEntry fromJson(JSONObject obj) {
            AutoAnswerEntry entry = new AutoAnswerEntry();
            entry.userId = obj.optLong("user_id", 0);
            entry.mode = obj.optInt("mode", AUTO_ANSWER_AUDIO_ONLY);
            return entry;
        }
    }
    
    public static final int SERVER_TYPE_TURN = 0;
    public static final int SERVER_TYPE_STUN = 1;
    
    public static class TurnServer {
        public String host;
        public int port;
        public String username;
        public String password;
        public boolean enabled;
        public int serverType; // SERVER_TYPE_TURN or SERVER_TYPE_STUN
        
        public TurnServer() {
            this.host = "";
            this.port = 3478;
            this.username = "";
            this.password = "";
            this.enabled = true;
            this.serverType = SERVER_TYPE_TURN;
        }
        
        public TurnServer(String host, int port, String username, String password) {
            this.host = host;
            this.port = port;
            this.username = username;
            this.password = password;
            this.enabled = true;
            this.serverType = SERVER_TYPE_TURN;
        }
        
        public TurnServer(String host, int port, String username, String password, int serverType) {
            this.host = host;
            this.port = port;
            this.username = username;
            this.password = password;
            this.enabled = true;
            this.serverType = serverType;
        }
        
        public JSONObject toJson() {
            try {
                JSONObject obj = new JSONObject();
                obj.put("host", host);
                obj.put("port", port);
                obj.put("username", username);
                obj.put("password", password);
                obj.put("enabled", enabled);
                obj.put("server_type", serverType);
                return obj;
            } catch (Exception e) {
                return new JSONObject();
            }
        }
        
        public static TurnServer fromJson(JSONObject obj) {
            TurnServer server = new TurnServer();
            server.host = obj.optString("host", "");
            server.port = obj.optInt("port", 3478);
            server.username = obj.optString("username", "");
            server.password = obj.optString("password", "");
            server.enabled = obj.optBoolean("enabled", true);
            server.serverType = obj.optInt("server_type", SERVER_TYPE_TURN);
            return server;
        }
        
        public String getUri() {
            String prefix = serverType == SERVER_TYPE_STUN ? "stun:" : "turn:";
            return prefix + host + ":" + port;
        }
        
        public boolean isValid() {
            return host != null && !host.isEmpty() && port > 0;
        }
        
        public boolean isTurn() {
            return serverType == SERVER_TYPE_TURN;
        }
        
        public boolean isStun() {
            return serverType == SERVER_TYPE_STUN;
        }
    }
    
    public static CallSettingsManager getInstance() {
        if (instance == null) {
            synchronized (CallSettingsManager.class) {
                if (instance == null) {
                    instance = new CallSettingsManager();
                }
            }
        }
        return instance;
    }
    
    private CallSettingsManager() {
        loadSettings();
    }
    
    private File getConfigFile() {
        return new File(ApplicationLoader.applicationContext.getFilesDir(), CONFIG_FILE);
    }
    
    private void loadSettings() {
        try {
            File file = getConfigFile();
            if (!file.exists()) {
                return;
            }
            
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();
            
            JSONObject json = new JSONObject(new String(data, "UTF-8"));
            
            forceWebRTC = json.optBoolean("force_webrtc", false);
            useTCP = json.optBoolean("use_tcp", false);
            replaceStandardServers = json.optBoolean("replace_standard", false);
            disableP2P = json.optBoolean("disable_p2p", false);
            useCallServer = json.optBoolean("use_call_server", false);
            callServerUrl = json.optString("call_server_url", "");
            preferredVideoCodec = json.optInt("preferred_video_codec", VIDEO_CODEC_AUTO);
            showDebugInfo = json.optBoolean("show_debug_info", false);
            
            // Load blacklist
            blacklist.clear();
            JSONArray blacklistArray = json.optJSONArray("blacklist");
            if (blacklistArray != null) {
                for (int i = 0; i < blacklistArray.length(); i++) {
                    blacklist.add(blacklistArray.getLong(i));
                }
            }
            
            // Load whitelist
            whitelistEnabled = json.optBoolean("whitelist_enabled", false);
            whitelist.clear();
            JSONArray whitelistArray = json.optJSONArray("whitelist");
            if (whitelistArray != null) {
                for (int i = 0; i < whitelistArray.length(); i++) {
                    whitelist.add(whitelistArray.getLong(i));
                }
            }
            
            // Load auto-answer list
            autoAnswerList.clear();
            JSONArray autoAnswerArray = json.optJSONArray("auto_answer");
            if (autoAnswerArray != null) {
                for (int i = 0; i < autoAnswerArray.length(); i++) {
                    JSONObject entryJson = autoAnswerArray.getJSONObject(i);
                    autoAnswerList.add(AutoAnswerEntry.fromJson(entryJson));
                }
            }
            
            customTurnServers.clear();
            JSONArray serversArray = json.optJSONArray("turn_servers");
            if (serversArray != null) {
                for (int i = 0; i < serversArray.length(); i++) {
                    JSONObject serverJson = serversArray.getJSONObject(i);
                    customTurnServers.add(TurnServer.fromJson(serverJson));
                }
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
    
    private void saveSettings() {
        try {
            JSONObject json = new JSONObject();
            json.put("force_webrtc", forceWebRTC);
            json.put("use_tcp", useTCP);
            json.put("replace_standard", replaceStandardServers);
            json.put("disable_p2p", disableP2P);
            json.put("use_call_server", useCallServer);
            json.put("call_server_url", callServerUrl);
            json.put("preferred_video_codec", preferredVideoCodec);
            json.put("show_debug_info", showDebugInfo);
            
            // Save blacklist
            JSONArray blacklistArray = new JSONArray();
            for (Long userId : blacklist) {
                blacklistArray.put(userId);
            }
            json.put("blacklist", blacklistArray);
            
            // Save whitelist
            json.put("whitelist_enabled", whitelistEnabled);
            JSONArray whitelistArray = new JSONArray();
            for (Long userId : whitelist) {
                whitelistArray.put(userId);
            }
            json.put("whitelist", whitelistArray);
            
            // Save auto-answer list
            JSONArray autoAnswerArray = new JSONArray();
            for (AutoAnswerEntry entry : autoAnswerList) {
                autoAnswerArray.put(entry.toJson());
            }
            json.put("auto_answer", autoAnswerArray);
            
            JSONArray serversArray = new JSONArray();
            for (TurnServer server : customTurnServers) {
                serversArray.put(server.toJson());
            }
            json.put("turn_servers", serversArray);
            
            FileOutputStream fos = new FileOutputStream(getConfigFile());
            fos.write(json.toString().getBytes("UTF-8"));
            fos.close();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }
    
    // Getters and Setters
    
    public boolean isForceWebRTC() {
        return forceWebRTC;
    }
    
    public void setForceWebRTC(boolean force) {
        this.forceWebRTC = force;
        saveSettings();
    }
    
    public boolean isUseTCP() {
        return useTCP;
    }
    
    public void setUseTCP(boolean useTCP) {
        this.useTCP = useTCP;
        saveSettings();
    }
    
    public boolean isReplaceStandardServers() {
        return replaceStandardServers;
    }
    
    public void setReplaceStandardServers(boolean replace) {
        this.replaceStandardServers = replace;
        saveSettings();
    }
    
    public boolean isDisableP2P() {
        return disableP2P;
    }
    
    public void setDisableP2P(boolean disable) {
        this.disableP2P = disable;
        saveSettings();
    }
    
    // Effective settings - returns server mode values when useCallServer is true
    // These should be used in actual call logic
    
    public boolean getEffectiveForceWebRTC() {
        return useCallServer ? true : forceWebRTC;
    }
    
    public boolean getEffectiveUseTCP() {
        // When using call server, TCP is not forced - server provides TURN servers
        // which may have their own transport settings (some TCP, some UDP)
        return useCallServer ? false : useTCP;
    }
    
    public boolean getEffectiveReplaceStandardServers() {
        return useCallServer ? true : replaceStandardServers;
    }
    
    public boolean getEffectiveDisableP2P() {
        return useCallServer ? true : disableP2P;
    }
    
    public boolean isUseCallServer() {
        return useCallServer;
    }
    
    public void setUseCallServer(boolean use) {
        this.useCallServer = use;
        saveSettings();
    }
    
    public String getCallServerUrl() {
        return callServerUrl;
    }
    
    public void setCallServerUrl(String url) {
        this.callServerUrl = url != null ? url : "";
        saveSettings();
    }
    
    public int getPreferredVideoCodec() {
        return preferredVideoCodec;
    }
    
    public void setPreferredVideoCodec(int codec) {
        this.preferredVideoCodec = codec;
        saveSettings();
    }
    
    public String getVideoCodecName() {
        switch (preferredVideoCodec) {
            case VIDEO_CODEC_H264: return "H.264";
            case VIDEO_CODEC_H265: return "H.265";
            default: return "Auto";
        }
    }
    
    public boolean isShowDebugInfo() {
        return showDebugInfo;
    }
    
    public void setShowDebugInfo(boolean show) {
        this.showDebugInfo = show;
        saveSettings();
    }
    
    public List<TurnServer> getCustomTurnServers() {
        return new ArrayList<>(customTurnServers);
    }
    
    public List<TurnServer> getEnabledTurnServers() {
        List<TurnServer> enabled = new ArrayList<>();
        for (TurnServer server : customTurnServers) {
            if (server.enabled && server.isValid()) {
                enabled.add(server);
            }
        }
        return enabled;
    }
    
    public void addTurnServer(TurnServer server) {
        customTurnServers.add(server);
        saveSettings();
    }
    
    public void removeTurnServer(int index) {
        if (index >= 0 && index < customTurnServers.size()) {
            customTurnServers.remove(index);
            saveSettings();
        }
    }
    
    public void updateTurnServer(int index, TurnServer server) {
        if (index >= 0 && index < customTurnServers.size()) {
            customTurnServers.set(index, server);
            saveSettings();
        }
    }
    
    public void toggleTurnServer(int index) {
        if (index >= 0 && index < customTurnServers.size()) {
            customTurnServers.get(index).enabled = !customTurnServers.get(index).enabled;
            saveSettings();
        }
    }
    
    public boolean hasCustomTurnServers() {
        return !getEnabledTurnServers().isEmpty();
    }
    
    // Blacklist methods
    
    public List<Long> getBlacklist() {
        return new ArrayList<>(blacklist);
    }
    
    public boolean isBlacklisted(long userId) {
        return blacklist.contains(userId);
    }
    
    public void addToBlacklist(long userId) {
        if (!blacklist.contains(userId)) {
            blacklist.add(userId);
            saveSettings();
        }
    }
    
    public void removeFromBlacklist(long userId) {
        if (blacklist.remove(userId)) {
            saveSettings();
        }
    }
    
    // Whitelist methods
    
    public boolean isWhitelistEnabled() {
        return whitelistEnabled;
    }
    
    public void setWhitelistEnabled(boolean enabled) {
        this.whitelistEnabled = enabled;
        saveSettings();
    }
    
    public List<Long> getWhitelist() {
        return new ArrayList<>(whitelist);
    }
    
    public boolean isWhitelisted(long userId) {
        return whitelist.contains(userId);
    }
    
    public void addToWhitelist(long userId) {
        if (!whitelist.contains(userId)) {
            whitelist.add(userId);
            saveSettings();
        }
    }
    
    public void removeFromWhitelist(long userId) {
        if (whitelist.remove(userId)) {
            saveSettings();
        }
    }
    
    // Auto-answer methods
    
    public List<AutoAnswerEntry> getAutoAnswerList() {
        return new ArrayList<>(autoAnswerList);
    }
    
    public AutoAnswerEntry getAutoAnswerEntry(long userId) {
        for (AutoAnswerEntry entry : autoAnswerList) {
            if (entry.userId == userId) {
                return entry;
            }
        }
        return null;
    }
    
    public boolean isAutoAnswer(long userId) {
        return getAutoAnswerEntry(userId) != null;
    }
    
    public void addAutoAnswer(long userId, int mode) {
        AutoAnswerEntry existing = getAutoAnswerEntry(userId);
        if (existing != null) {
            existing.mode = mode;
        } else {
            autoAnswerList.add(new AutoAnswerEntry(userId, mode));
        }
        saveSettings();
    }
    
    public void removeAutoAnswer(long userId) {
        autoAnswerList.removeIf(entry -> entry.userId == userId);
        saveSettings();
    }
    
    /**
     * Check if an incoming call should be rejected based on blacklist/whitelist settings
     * @param userId The user ID of the caller
     * @return true if the call should be rejected
     */
    public boolean shouldRejectCall(long userId) {
        // First check blacklist
        if (isBlacklisted(userId)) {
            return true;
        }
        // Then check whitelist (if enabled)
        if (whitelistEnabled && !isWhitelisted(userId)) {
            return true;
        }
        return false;
    }
    
    /**
     * Check if a call should be auto-answered
     * @param userId The user ID of the caller
     * @param isVideoCall Whether the incoming call is a video call
     * @return true if the call should be auto-answered
     */
    public boolean shouldAutoAnswer(long userId, boolean isVideoCall) {
        AutoAnswerEntry entry = getAutoAnswerEntry(userId);
        if (entry == null) {
            return false;
        }
        // If audio-only mode is set, don't auto-answer video calls
        if (entry.mode == AUTO_ANSWER_AUDIO_ONLY && isVideoCall) {
            return false;
        }
        return true;
    }
    
    // Message prefix for sharing settings (emoji header + base64 encoded JSON)
    public static final String SETTINGS_PREFIX = "📞🔧 CryptoGram Call Settings\n";
    public static final String SETTINGS_DATA_PREFIX = "DATA:";
    
    /**
     * Export current settings as a shareable base64-encoded string with emoji header
     */
    public String exportSettingsForSharing() {
        try {
            JSONObject json = new JSONObject();
            json.put("force_webrtc", forceWebRTC);
            json.put("use_tcp", useTCP);
            json.put("replace_standard", replaceStandardServers);
            json.put("disable_p2p", disableP2P);
            
            JSONArray serversArray = new JSONArray();
            for (TurnServer server : customTurnServers) {
                serversArray.put(server.toJson());
            }
            json.put("turn_servers", serversArray);
            
            // Encode JSON to base64
            String base64 = android.util.Base64.encodeToString(
                json.toString().getBytes("UTF-8"), 
                android.util.Base64.NO_WRAP
            );
            
            return SETTINGS_PREFIX + SETTINGS_DATA_PREFIX + base64;
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }
    
    /**
     * Check if a message contains call settings
     */
    public static boolean isCallSettingsMessage(String text) {
        if (text == null) return false;
        return text.contains(SETTINGS_DATA_PREFIX) && text.contains("CryptoGram Call Settings");
    }
    
    /**
     * Extract base64 data from message
     */
    private static String extractBase64Data(String message) {
        int dataIndex = message.indexOf(SETTINGS_DATA_PREFIX);
        if (dataIndex < 0) return null;
        return message.substring(dataIndex + SETTINGS_DATA_PREFIX.length()).trim();
    }
    
    /**
     * Import settings from a shared message
     * @return true if successful
     */
    public boolean importSettingsFromMessage(String message) {
        if (!isCallSettingsMessage(message)) {
            return false;
        }
        
        try {
            String base64 = extractBase64Data(message);
            if (base64 == null) return false;
            
            // Decode base64 to JSON
            byte[] decodedBytes = android.util.Base64.decode(base64, android.util.Base64.NO_WRAP);
            String jsonStr = new String(decodedBytes, "UTF-8");
            JSONObject json = new JSONObject(jsonStr);
            
            forceWebRTC = json.optBoolean("force_webrtc", false);
            useTCP = json.optBoolean("use_tcp", false);
            replaceStandardServers = json.optBoolean("replace_standard", false);
            disableP2P = json.optBoolean("disable_p2p", false);
            
            customTurnServers.clear();
            JSONArray serversArray = json.optJSONArray("turn_servers");
            if (serversArray != null) {
                for (int i = 0; i < serversArray.length(); i++) {
                    JSONObject serverJson = serversArray.getJSONObject(i);
                    customTurnServers.add(TurnServer.fromJson(serverJson));
                }
            }
            
            saveSettings();
            return true;
        } catch (Exception e) {
            FileLog.e(e);
            return false;
        }
    }
    
    /**
     * Get human-readable summary of settings in a message
     */
    public static String getSettingsSummary(String message) {
        if (!isCallSettingsMessage(message)) {
            return null;
        }
        
        try {
            String base64 = extractBase64Data(message);
            if (base64 == null) return null;
            
            byte[] decodedBytes = android.util.Base64.decode(base64, android.util.Base64.NO_WRAP);
            String jsonStr = new String(decodedBytes, "UTF-8");
            JSONObject json = new JSONObject(jsonStr);
            
            StringBuilder sb = new StringBuilder();
            sb.append("📞 Call Settings:\n");
            
            if (json.optBoolean("force_webrtc", false)) {
                sb.append("• Force WebRTC: ON\n");
            }
            if (json.optBoolean("use_tcp", false)) {
                sb.append("• Use TCP: ON\n");
            }
            if (json.optBoolean("disable_p2p", false)) {
                sb.append("• Disable P2P: ON\n");
            }
            if (json.optBoolean("replace_standard", false)) {
                sb.append("• Replace standard servers: ON\n");
            }
            
            JSONArray serversArray = json.optJSONArray("turn_servers");
            if (serversArray != null && serversArray.length() > 0) {
                sb.append("• Servers: ").append(serversArray.length()).append("\n");
            }
            
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }
}

