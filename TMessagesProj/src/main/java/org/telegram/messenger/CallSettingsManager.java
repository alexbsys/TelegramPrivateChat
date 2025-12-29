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
    
    // Message prefix for sharing settings
    public static final String SETTINGS_PREFIX = "📞CALLSETTINGS:";
    
    /**
     * Export current settings as a shareable JSON string with prefix
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
            
            return SETTINGS_PREFIX + json.toString();
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }
    
    /**
     * Check if a message contains call settings
     */
    public static boolean isCallSettingsMessage(String text) {
        return text != null && text.startsWith(SETTINGS_PREFIX);
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
            String jsonStr = message.substring(SETTINGS_PREFIX.length());
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
            String jsonStr = message.substring(SETTINGS_PREFIX.length());
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

