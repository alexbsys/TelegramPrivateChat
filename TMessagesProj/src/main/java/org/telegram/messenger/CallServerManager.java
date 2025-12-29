/*
 * Call Server Manager - handles communication with external call management server
 * for dynamic TURN server allocation and tariff management
 */

package org.telegram.messenger;

import android.provider.Settings;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class CallServerManager {

    private static volatile CallServerManager instance;
    
    // Response status
    public static final String STATUS_OK = "ok";
    public static final String STATUS_ERROR = "error";
    
    // Tariff types
    public static final String TARIFF_FREE = "FREE";
    public static final String TARIFF_PAID = "PAID";
    
    // Callback interfaces
    public interface TurnServersCallback {
        void onSuccess(TurnServersResponse response);
        void onError(String errorHtml);
    }
    
    public interface TariffCallback {
        void onSuccess(TariffResponse response);
        void onError(String error);
    }
    
    // Response classes
    public static class TurnServersResponse {
        public String tariff; // FREE or PAID
        public double freeMinutesRemaining; // -1 = don't show
        public String periodEnd; // ISO date
        public List<CallSettingsManager.TurnServer> servers;
        
        public boolean shouldShowTimer() {
            return TARIFF_FREE.equals(tariff) && freeMinutesRemaining >= 0;
        }
        
        public boolean shouldShowPeriodEnd() {
            return periodEnd != null && !periodEnd.isEmpty();
        }
    }
    
    public static class TariffResponse {
        public String tariff;
        public double freeMinutesRemaining; // -1 for PAID
        public String periodEnd;
    }
    
    public static CallServerManager getInstance() {
        if (instance == null) {
            synchronized (CallServerManager.class) {
                if (instance == null) {
                    instance = new CallServerManager();
                }
            }
        }
        return instance;
    }
    
    private CallServerManager() {
    }
    
    /**
     * Get hashed device ID for authentication
     */
    public String getDeviceIdHash() {
        try {
            String androidId = Settings.Secure.getString(
                ApplicationLoader.applicationContext.getContentResolver(),
                Settings.Secure.ANDROID_ID
            );
            if (androidId == null || androidId.isEmpty()) {
                androidId = "unknown";
            }
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(androidId.getBytes("UTF-8"));
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            FileLog.e(e);
            return "error";
        }
    }
    
    /**
     * Get current language code
     */
    public String getLanguageCode() {
        String lang = LocaleController.getLocaleStringIso639();
        if (lang == null || lang.isEmpty()) {
            lang = Locale.getDefault().getLanguage();
        }
        if (lang == null || lang.isEmpty()) {
            lang = "en";
        }
        return lang;
    }
    
    /**
     * Fetch TURN servers for a call
     * @param callId Telegram call ID
     * @param callback Result callback
     */
    public void fetchTurnServers(long callId, TurnServersCallback callback) {
        String baseUrl = CallSettingsManager.getInstance().getCallServerUrl();
        if (baseUrl == null || baseUrl.isEmpty()) {
            callback.onError("Call server URL not configured");
            return;
        }
        
        // Build URL
        String url = baseUrl;
        if (!url.endsWith("/")) {
            url += "/";
        }
        url += "turn-servers?call_id=" + callId 
            + "&device_id=" + getDeviceIdHash()
            + "&lang=" + getLanguageCode();
        
        final String finalUrl = url;
        
        Utilities.globalQueue.postRunnable(() -> {
            try {
                String response = makeGetRequest(finalUrl);
                JSONObject json = new JSONObject(response);
                
                String status = json.optString("status", STATUS_ERROR);
                
                if (STATUS_ERROR.equals(status)) {
                    String errorHtml = json.optString("error_html", "Unknown error");
                    AndroidUtilities.runOnUIThread(() -> callback.onError(errorHtml));
                    return;
                }
                
                TurnServersResponse result = new TurnServersResponse();
                result.tariff = json.optString("tariff", TARIFF_FREE);
                result.freeMinutesRemaining = json.optDouble("free_minutes_remaining", -1);
                result.periodEnd = json.optString("period_end", "");
                
                result.servers = new ArrayList<>();
                JSONArray serversArray = json.optJSONArray("servers");
                if (serversArray != null) {
                    for (int i = 0; i < serversArray.length(); i++) {
                        JSONObject serverJson = serversArray.getJSONObject(i);
                        CallSettingsManager.TurnServer server = new CallSettingsManager.TurnServer();
                        server.host = serverJson.optString("host", "");
                        server.port = serverJson.optInt("port", 3478);
                        server.username = serverJson.optString("username", "");
                        server.password = serverJson.optString("password", "");
                        server.enabled = true;
                        
                        String type = serverJson.optString("type", "turn");
                        server.serverType = "stun".equalsIgnoreCase(type) 
                            ? CallSettingsManager.SERVER_TYPE_STUN 
                            : CallSettingsManager.SERVER_TYPE_TURN;
                        
                        if (server.isValid()) {
                            result.servers.add(server);
                        }
                    }
                }
                
                AndroidUtilities.runOnUIThread(() -> callback.onSuccess(result));
                
            } catch (Exception e) {
                FileLog.e(e);
                AndroidUtilities.runOnUIThread(() -> callback.onError("Connection error: " + e.getMessage()));
            }
        });
    }
    
    /**
     * Query current tariff information
     * @param callback Result callback
     */
    public void queryTariff(TariffCallback callback) {
        String baseUrl = CallSettingsManager.getInstance().getCallServerUrl();
        if (baseUrl == null || baseUrl.isEmpty()) {
            callback.onError("Call server URL not configured");
            return;
        }
        
        // Build URL
        String url = baseUrl;
        if (!url.endsWith("/")) {
            url += "/";
        }
        url += "query-tariff?id=" + getDeviceIdHash()
            + "&lang=" + getLanguageCode();
        
        final String finalUrl = url;
        
        Utilities.globalQueue.postRunnable(() -> {
            try {
                String response = makeGetRequest(finalUrl);
                JSONObject json = new JSONObject(response);
                
                String status = json.optString("status", STATUS_ERROR);
                
                if (STATUS_ERROR.equals(status)) {
                    String error = json.optString("error_html", json.optString("error", "Unknown error"));
                    AndroidUtilities.runOnUIThread(() -> callback.onError(error));
                    return;
                }
                
                TariffResponse result = new TariffResponse();
                result.tariff = json.optString("tariff", TARIFF_FREE);
                result.freeMinutesRemaining = json.optDouble("free_minutes_remaining", -1);
                result.periodEnd = json.optString("period_end", "");
                
                AndroidUtilities.runOnUIThread(() -> callback.onSuccess(result));
                
            } catch (Exception e) {
                FileLog.e(e);
                AndroidUtilities.runOnUIThread(() -> callback.onError("Connection error: " + e.getMessage()));
            }
        });
    }
    
    /**
     * Make HTTP GET request
     */
    private String makeGetRequest(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(10000);
        connection.setReadTimeout(10000);
        
        int responseCode = connection.getResponseCode();
        
        BufferedReader reader;
        if (responseCode >= 200 && responseCode < 300) {
            reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        } else {
            reader = new BufferedReader(new InputStreamReader(connection.getErrorStream()));
        }
        
        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        return response.toString();
    }
}

