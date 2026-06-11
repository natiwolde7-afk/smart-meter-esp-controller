#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <Preferences.h>
#include "mbedtls/md.h"
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi.h>

#define RELAY_PIN   5
#define VOLTAGE_PIN 34
#define CURRENT_PIN 35
#define METER_ID    1

const int WIFI_CHANNEL = 1;

uint8_t gatewayMAC[] = {0xC4, 0x5B, 0xBE,
                         0x4A, 0xB9, 0x49};

LiquidCrystal_I2C lcd(0x27, 16, 2);
Preferences preferences;

const char* secretKey = "SmartMeterKey2024";

float voltageCalibration = 219.0;
float currentCalibration = 111.1;

float Vrms     = 0;
float Irms     = 0;
float watts    = 0;
float wattHour = 0;
float kWh      = 0;

unsigned long lastTime = 0;
bool relayStatus = true;

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

MeterData outgoingData;

// HMAC Function
String generateHMAC(String message) {
  byte hmacResult[32];
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx,
    mbedtls_md_info_from_type(md_type), 1);
  mbedtls_md_hmac_starts(&ctx,
    (const unsigned char*)secretKey,
    strlen(secretKey));
  mbedtls_md_hmac_update(&ctx,
    (const unsigned char*)message.c_str(),
    message.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  String result = "";
  for (int i = 0; i < 32; i++) {
    if (hmacResult[i] < 16) result += "0";
    result += String(hmacResult[i], HEX);
  }
  return result;
}

bool verifyHMAC(String message, String signature) {
  return generateHMAC(message).equals(signature);
}

// ESP-NOW Send Callback
void onSent(const wifi_tx_info_t *info,
            esp_now_send_status_t status) {
  Serial.print("ESP-NOW Send: ");
  Serial.println(status == ESP_NOW_SEND_SUCCESS ?
    "Success" : "Failed");
}

// ESP-NOW Receive Callback
void onReceive(const esp_now_recv_info *info,
               const uint8_t *data, int len) {

  Serial.println("Command received!");
  ServerCommand cmd;
  memcpy(&cmd, data, sizeof(cmd));

  Serial.print("Target Meter: ");
  Serial.println(cmd.targetMeter);
  Serial.print("Command: ");
  Serial.println(cmd.command);

  if (cmd.targetMeter != METER_ID &&
      cmd.targetMeter != 0) {
    Serial.println("Wrong meter ID!");
    return;
  }

  // HMAC Verification
  String cmdMessage = "CMD:" +
                      String(cmd.targetMeter) +
                      ":" + String(cmd.command);
  String expectedHMAC = generateHMAC(cmdMessage);
  String receivedHMAC = String(cmd.hmac);

  Serial.print("Expected: "); Serial.println(expectedHMAC);
  Serial.print("Received: "); Serial.println(receivedHMAC);
  Serial.print("Match: ");
  Serial.println(expectedHMAC.equals(receivedHMAC) ?
    "YES" : "NO");

  if (!expectedHMAC.equals(receivedHMAC)) {
    Serial.println("Invalid command rejected!");
    return;
  }

  Serial.println("Verified command accepted!");

  if (strcmp(cmd.command, "RELAY_OFF") == 0) {
    digitalWrite(RELAY_PIN, HIGH);
    relayStatus = false;
    reinitLCD();
    Serial.println("Relay OFF - Server command");
  }
  else if (strcmp(cmd.command, "RELAY_ON") == 0) {
    digitalWrite(RELAY_PIN, LOW);
    relayStatus = true;
    reinitLCD();
    Serial.println("Relay ON - Server command");
  }
}

// LCD Reinit
void reinitLCD() {
  delay(300);
  Wire.begin(21, 22);
  Wire.setClock(5000);
  lcd.init();
  lcd.init();
  lcd.backlight();
  lcd.clear();
}

// Flash Storage
void saveKWh() {
  preferences.begin("meter", false);
  preferences.putFloat("kwh", kWh);
  preferences.putFloat("wh",  wattHour);
  preferences.end();
}

void loadKWh() {
  preferences.begin("meter", true);
  kWh      = preferences.getFloat("kwh", 0.0);
  wattHour = preferences.getFloat("wh",  0.0);
  preferences.end();
  Serial.print("Loaded kWh: ");
  Serial.println(kWh, 4);
}

// RMS Functions
float getVrms() {
  float sumSquared = 0;
  float offset     = 0;
  int   samples    = 1000;

  for (int i = 0; i < samples; i++) {
    offset += analogRead(VOLTAGE_PIN);
    delayMicroseconds(100);
  }
  offset /= samples;

  for (int i = 0; i < samples; i++) {
    float raw = analogRead(VOLTAGE_PIN) - offset;
    sumSquared += raw * raw;
    delayMicroseconds(100);
  }
  return (sqrt(sumSquared / samples) / 4095.0)
         * 3.3 * voltageCalibration;
}

float getIrms() {
  float sumSquared = 0;
  float offset     = 0;
  int   samples    = 1000;

  for (int i = 0; i < samples; i++) {
    offset += analogRead(CURRENT_PIN);
    delayMicroseconds(100);
  }
  offset /= samples;

  for (int i = 0; i < samples; i++) {
    float raw = analogRead(CURRENT_PIN) - offset;
    sumSquared += raw * raw;
    delayMicroseconds(100);
  }
  return (sqrt(sumSquared / samples) / 4095.0)
         * 3.3 * currentCalibration;
}

// Setup
void setup() {
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);
  relayStatus = true;

  Serial.begin(115200);
  delay(1000);

  loadKWh();

  // Set WiFi channel to match ESP8266
  WiFi.mode(WIFI_STA);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(WIFI_CHANNEL,
                       WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(false);

  Serial.print("ESP32 MAC: ");
  Serial.println(WiFi.macAddress());
  Serial.print("ESP-NOW Channel: ");
  Serial.println(WIFI_CHANNEL);

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed!");
    return;
  }
  esp_now_register_send_cb(onSent);
  esp_now_register_recv_cb(onReceive);

  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, gatewayMAC, 6);
  peerInfo.channel = WIFI_CHANNEL;
  peerInfo.encrypt = false;
  esp_now_add_peer(&peerInfo);

  Wire.begin(21, 22);
  Wire.setClock(5000);
  delay(500);
  lcd.init();
  delay(100);
  lcd.init();
  delay(100);
  lcd.backlight();
  delay(100);
  lcd.clear();
  delay(200);

  lcd.setCursor(0, 0);
  lcd.print("Smart Meter v1");
  lcd.setCursor(0, 1);
  lcd.print("HMAC Secured");
  delay(2000);
  lcd.clear();

  lastTime = millis();
  Serial.println("Ready - ON/OFF/RESET/SAVE");
}

// Loop
void loop() {

  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    command.trim();

    if (command.equalsIgnoreCase("on")) {
      digitalWrite(RELAY_PIN, LOW);
      relayStatus = true;
      reinitLCD();
      Serial.println("Relay ON");
    }
    else if (command.equalsIgnoreCase("off")) {
      digitalWrite(RELAY_PIN, HIGH);
      relayStatus = false;
      reinitLCD();
      Serial.println("Relay OFF");
    }
    else if (command.equalsIgnoreCase("reset")) {
      kWh = 0; wattHour = 0;
      saveKWh();
      Serial.println("Energy reset");
    }
    else if (command.equalsIgnoreCase("save")) {
      saveKWh();
      Serial.println("Saved!");
    }
  }

  static unsigned long lastUpdate = 0;
  if (millis() - lastUpdate >= 10000) {
    lastUpdate = millis();

    Vrms  = getVrms();
    Irms  = getIrms();

    if (Vrms < 5.0)  Vrms = 0;
    if (Irms < 0.5)  Irms = 0;

    watts = Vrms * Irms;

    unsigned long now = millis();
    float elapsedHours = (now - lastTime) / 3600000.0;
    lastTime = now;

    if (Vrms > 5.0 && Irms > 0.5) {
      wattHour += watts * elapsedHours;
      kWh = wattHour / 1000.0;
    }

    static unsigned long lastSave = 0;
    if (millis() - lastSave >= 300000) {
      lastSave = millis();
      saveKWh();
    }

    String meterMsg = "METER:" + String(METER_ID) +
                      ":V:" + String(Vrms, 1) +
                      ":I:" + String(Irms, 2) +
                      ":W:" + String(watts, 1) +
                      ":KWH:" + String(kWh, 4);
    String signature = generateHMAC(meterMsg);

    outgoingData.meterID     = METER_ID;
    outgoingData.vrms        = Vrms;
    outgoingData.irms        = Irms;
    outgoingData.watts       = watts;
    outgoingData.kWh         = kWh;
    outgoingData.relayStatus = relayStatus;
    signature.toCharArray(outgoingData.hmac, 65);

    esp_now_send(gatewayMAC,
                 (uint8_t*)&outgoingData,
                 sizeof(outgoingData));

    Serial.println("─────────────────────────");
    Serial.print("Vrms:  "); Serial.print(Vrms, 1);
    Serial.println(" V");
    Serial.print("Irms:  "); Serial.print(Irms, 2);
    Serial.println(" A");
    Serial.print("Power: "); Serial.print(watts, 1);
    Serial.println(" W");
    Serial.print("kWh:   "); Serial.print(kWh, 4);
    Serial.println(" kWh");
    Serial.print("HMAC:  "); Serial.println(signature);
    Serial.print("Relay: ");
    Serial.println(relayStatus ? "ON" : "OFF");

    static int displayPage = 0;
    static unsigned long lastPage = 0;

    if (millis() - lastPage >= 3000) {
      lastPage = millis();
      displayPage = (displayPage + 1) % 3;
      lcd.clear();
    }

    switch (displayPage) {
      case 0:
        lcd.setCursor(0, 0);
        lcd.print("V:"); lcd.print(Vrms, 1);
        lcd.print("V        ");
        lcd.setCursor(0, 1);
        lcd.print("I:"); lcd.print(Irms, 2);
        lcd.print("A        ");
        break;
      case 1:
        lcd.setCursor(0, 0);
        lcd.print("Power:          ");
        lcd.setCursor(0, 1);
        lcd.print(watts, 1);
        lcd.print("W           ");
        break;
      case 2:
        lcd.setCursor(0, 0);
        lcd.print("Energy:         ");
        lcd.setCursor(0, 1);
        lcd.print(kWh, 4);
        lcd.print(" kWh      ");
        break;
    }
  }
}
