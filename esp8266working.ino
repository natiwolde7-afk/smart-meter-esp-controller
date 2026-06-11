#include <ArduinoJson.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>
#include <espnow.h>
#include <bearssl/bearssl_hmac.h>

// --- Configuration ---
const char *ssid = "DESKTOP-PU5F996 7618";
const char *password = "nati1229";
const char *serverUrl = "http://192.168.137.245:5000/api/device/data";
const char *apiToken = "my_secure_token_123";
const char *secretKey = "SmartMeterKey2024";

// --- Data Structures (MUST MATCH ESP32) ---
typedef struct {
  int   meterID;
  float vrms;
  float irms;
  float watts;
  float kWh;
  bool  relayStatus;
  char  hmac[65];
} MeterData;

typedef struct {
  int  targetMeter;
  char command[20];
  char hmac[65];
} ServerCommand;

MeterData incomingData;
MeterData queuedData;
bool newMeterDataReady = false;

// --- Global Variables ---
WiFiClient wifiClient;
HTTPClient http;
unsigned long lastStatusCheck = 0;
const unsigned long statusInterval = 10000; 

// Dynamic Runtime Tracking (Learned from live ESP32 ESP-NOW packets)
int activeMeterID = 1; // Default fallback ID
uint8_t activeMeterMAC[6] = {0xD4, 0xE9, 0xF4, 0xE9, 0xC3, 0xF8}; // Default fallback MAC

bool lastKnownRelayState = true;
bool hasReceivedMeterData = false;

// BearSSL HMAC
String generateHMAC(String message) {
  br_hmac_key_context kc;
  br_hmac_context ctx;
  unsigned char hmacResult[32];

  br_hmac_key_init(&kc, &br_sha256_vtable, secretKey, strlen(secretKey));
  br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, message.c_str(), message.length());
  br_hmac_out(&ctx, hmacResult);

  String result = "";
  for (int i = 0; i < 32; i++) {
    if (hmacResult[i] < 16) result += "0";
    result += String(hmacResult[i], HEX);
  }
  return result;
}

void sendCommand(int meterID, String command) {
  ServerCommand cmd;
  cmd.targetMeter = meterID;
  command.toCharArray(cmd.command, 20);

  String message = "CMD:" + String(meterID) + ":" + command;
  String signature = generateHMAC(message);
  signature.toCharArray(cmd.hmac, 65);

  Serial.print("Sending Command to Meter "); Serial.print(meterID); Serial.print(": "); Serial.println(command);
  Serial.print("Signature: "); Serial.println(signature);

  esp_now_send(activeMeterMAC, (uint8_t*)&cmd, sizeof(cmd));
}

// --- Backend Upload ---
void uploadToBackend(MeterData data) {
  if (WiFi.status() == WL_CONNECTED) {
    http.begin(wifiClient, serverUrl);
    http.addHeader("Content-Type", "application/json");
    http.addHeader("x-api-token", apiToken);

    char devId[16];
    sprintf(devId, "meter_%03d", data.meterID);

    // Server receives billing (wattHour), live relay status for dashboard verification, and security (HMAC)
    StaticJsonDocument<256> doc;
    doc["deviceId"] = devId;
    doc["wattHour"] = data.kWh * 1000.0;
    doc["vrms"] = data.vrms;
    doc["irms"] = data.irms;
    doc["watts"] = data.watts;
    doc["relayStatus"] = data.relayStatus ? "ON" : "OFF";
    doc["hmac"] = data.hmac;

    String jsonResponse;
    serializeJson(doc, jsonResponse);

    int httpResponseCode = http.POST(jsonResponse);

    if (httpResponseCode > 0) {
      Serial.print("Server Upload Success. HTTP Code: "); Serial.println(httpResponseCode);
      if (httpResponseCode == 200) {
        String responseStr = http.getString();
        Serial.print("Server Response: "); Serial.println(responseStr);
      }
    } else {
      Serial.print("Upload Failed. HTTP Error: "); Serial.println(httpResponseCode);
    }
    http.end();
  } else {
    Serial.println("Upload Failed: WiFi not connected.");
  }
}

// --- ESP-NOW Callback ---
void onDataRecv(uint8_t *mac, uint8_t *incomingRawData, uint8_t len) {
  if (len == sizeof(MeterData)) {
    memcpy(&incomingData, incomingRawData, sizeof(incomingData));

    // Dynamically learn the live meter ID and MAC address from the ESP32 packet
    activeMeterID = incomingData.meterID;
    memcpy(activeMeterMAC, mac, 6);

    Serial.println("\n--- [REAL-TIME TELEMETRY] ESP-NOW Packet Received ---");
    Serial.print("Meter ID: "); Serial.println(activeMeterID);
    Serial.print("Vrms: "); Serial.print(incomingData.vrms, 1); Serial.println(" V");
    Serial.print("Irms: "); Serial.print(incomingData.irms, 2); Serial.println(" A");
    Serial.print("Power: "); Serial.print(incomingData.watts, 1); Serial.println(" W");
    Serial.print("Energy: "); Serial.print(incomingData.kWh, 4); Serial.println(" kWh");
    Serial.print("Relay: "); Serial.println(incomingData.relayStatus ? "ON" : "OFF");
    Serial.print("HMAC: "); Serial.println(incomingData.hmac);

    // Verify HMAC from Meter
    String expectedMsg = "METER:" + String(incomingData.meterID) +
                      ":V:" + String(incomingData.vrms, 1) +
                      ":I:" + String(incomingData.irms, 2) +
                      ":W:" + String(incomingData.watts, 1) +
                      ":KWH:" + String(incomingData.kWh, 4);
    String expectedHMAC = generateHMAC(expectedMsg);

    if (!expectedHMAC.equals(String(incomingData.hmac))) {
      Serial.println("HMAC verification failed! Discarding packet.");
      return;
    }
    Serial.println("HMAC verified successfully!");

    lastKnownRelayState = incomingData.relayStatus;
    hasReceivedMeterData = true;

    // Defer the HTTP upload to the main loop to prevent crashing in the ESP-NOW callback
    memcpy(&queuedData, &incomingData, sizeof(MeterData));
    newMeterDataReady = true;
  } else {
    Serial.print("Error: Received size "); Serial.print(len); 
    Serial.print(" but expected "); Serial.println(sizeof(MeterData));
  }
}

// --- WiFi Connection ---
void connectWiFi() {
  Serial.print("Connecting to WiFi: ");
  Serial.println(ssid);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi Connected!");
  Serial.print("IP Address: "); Serial.println(WiFi.localIP());
  Serial.print("WiFi Channel: "); Serial.println(WiFi.channel());
  Serial.print("Gateway MAC: "); Serial.println(WiFi.macAddress());
}

// --- Status Check (Remote Shutdown) ---
void checkDeviceStatus() {
  if (WiFi.status() == WL_CONNECTED) {
    char statusUrl[128];
    // Dynamically poll the status of the active meter learned from ESP-NOW
    sprintf(statusUrl, "http://192.168.137.245:5000/api/device/meter_%03d/status", activeMeterID);

    http.begin(wifiClient, statusUrl);
    int httpResponseCode = http.GET();

    if (httpResponseCode == 200) {
      String payload = http.getString();
      StaticJsonDocument<500> doc;
      deserializeJson(doc, payload);

      const char *relayState = doc["relayState"]; 
      if (relayState) {
        bool desiredState = (strcmp(relayState, "ON") == 0);
        Serial.print("Relay Status from Server (Meter "); Serial.print(activeMeterID); Serial.print("): "); Serial.println(relayState);
        Serial.print("Gateway actual relay state tracking: "); Serial.println(lastKnownRelayState ? "ON" : "OFF");

        if (hasReceivedMeterData && desiredState != lastKnownRelayState) {
          if (desiredState) {
            sendCommand(activeMeterID, "RELAY_ON");
            lastKnownRelayState = true;
          } else {
            sendCommand(activeMeterID, "RELAY_OFF");
            lastKnownRelayState = false;
          }
        }
      }
    } else {
      Serial.print("Status Check Failed. HTTP Error: "); Serial.println(httpResponseCode);
    }
    http.end();
  }
}

void setup() {
  Serial.begin(115200);
  connectWiFi();

  if (esp_now_init() != 0) {
    Serial.println("Error initializing ESP-NOW");
    return;
  }

  esp_now_set_self_role(ESP_NOW_ROLE_COMBO);
  esp_now_register_recv_cb(onDataRecv);
  esp_now_add_peer(activeMeterMAC, ESP_NOW_ROLE_COMBO, WiFi.channel(), NULL, 0);

  Serial.println("\n==========================================");
  Serial.println("Gateway Ready. Waiting for live ESP32 ESP-NOW data...");
  Serial.println("--- SERIAL TESTING COMMANDS ---");
  Serial.println("Type 'TEST'   -> Simulate Meter Data Upload to Server");
  Serial.println("Type 'STATUS' -> Manually Poll Server Relay Status");
  Serial.println("Type 'ON'     -> Send ESP-NOW Relay ON Command");
  Serial.println("Type 'OFF'    -> Send ESP-NOW Relay OFF Command");
  Serial.println("Type 'FAKE'   -> Send Fake HMAC Command (Security Test)");
  Serial.println("==========================================");
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  // Handle deferred HTTP upload from the ESP-NOW callback
  if (newMeterDataReady) {
    newMeterDataReady = false;
    uploadToBackend(queuedData);
  }

  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();

    if (cmd.equalsIgnoreCase("on")) {
      sendCommand(activeMeterID, "RELAY_ON");
    }
    else if (cmd.equalsIgnoreCase("off")) {
      sendCommand(activeMeterID, "RELAY_OFF");
    }
    else if (cmd.equalsIgnoreCase("fake")) {
      ServerCommand fakecmd;
      fakecmd.targetMeter = activeMeterID;
      strcpy(fakecmd.command, "RELAY_OFF");
      strcpy(fakecmd.hmac, "0000000000000000000000000000000000000000000000000000000000000000");
      Serial.println("Sending FAKE command!");
      esp_now_send(activeMeterMAC, (uint8_t*)&fakecmd, sizeof(fakecmd));
    }
    else if (cmd.equalsIgnoreCase("test") || cmd.equalsIgnoreCase("simulate")) {
      Serial.println("\n--- [SIMULATION] Generating Mock Meter Data ---");
      MeterData mockData;
      mockData.meterID = activeMeterID;
      mockData.vrms = 228.5;
      mockData.irms = 3.2;
      mockData.watts = 731.2;
      mockData.kWh = 45.6789;
      mockData.relayStatus = lastKnownRelayState;

      String mockMsg = "METER:" + String(activeMeterID) + ":V:228.5:I:3.20:W:731.2:KWH:45.6789";
      String mockHMAC = generateHMAC(mockMsg);
      mockHMAC.toCharArray(mockData.hmac, 65);

      Serial.print("Mock Power: "); Serial.print(mockData.watts); Serial.println(" W");
      Serial.print("Mock Energy: "); Serial.print(mockData.kWh, 4); Serial.println(" kWh");
      Serial.print("Mock HMAC: "); Serial.println(mockData.hmac);
      Serial.println("Uploading mock data to backend server...");

      uploadToBackend(mockData);
    }
    else if (cmd.equalsIgnoreCase("status")) {
      Serial.println("\n--- [MANUAL STATUS CHECK] Polling Backend Server ---");
      checkDeviceStatus();
    }
    else {
      Serial.println("Unknown command. Type TEST, STATUS, ON, OFF, or FAKE.");
    }
  }

  if (millis() - lastStatusCheck > statusInterval) {
    checkDeviceStatus();
    lastStatusCheck = millis();
  }
}
