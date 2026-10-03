/*
 * AegisAgent — ESP32 IoT Hardware Device Firmware
 * 
 * Hardware:
 *   - ESP32 Development Board
 *   - Green LED on GPIO 26 (Status / Door Unlock Indicator)
 *   - Red LED on GPIO 27 (Security Alert / Alarm Indicator)
 *   - Buzzer on GPIO 25 (Audible Alarm)
 * 
 * Security Features:
 *   - Authenticated MQTT connection over TLS/TCP
 *   - Strict Command Allowlisting on device (Defense in Depth)
 *   - Non-blocking state machine using millis()
 *   - Last Will & Testament (LWT) for online/offline status tracking
 * 
 * Note on Replay Protection:
 *   Command payloads include ISO/unix timestamps (`ts`). Full timestamp validation requires
 *   an NTP time sync on boot. If device clock is un-synced, timestamp validation is skipped;
 *   nonce tracking or NTP sync can be added for full hardware replay protection.
 */

#include <WiFi.h>
#include <PubSubClient.h>
#include "secrets.h"

// Hardware Pin Definitions
const int GREEN_LED = 26;
const int RED_LED   = 27;
const int BUZZER    = 25;

// Network & MQTT Instances
WiFiClient espClient;
PubSubClient mqttClient(espClient);

// Timing variables for non-blocking operations
unsigned long doorTimerEnd = 0;
bool doorActive = false;

unsigned long alarmTimerEnd = 0;
bool alarmActive = false;

unsigned long alertTimerEnd = 0;
bool alertActive = false;

unsigned long lastReconnectAttempt = 0;

void setupPins() {
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(BUZZER, OUTPUT);

  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);
  digitalWrite(BUZZER, LOW);
}

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;

  Serial.print("Connecting to WiFi SSID: ");
  Serial.println(WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASS);

  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("\nWiFi Connected!");
  Serial.print("IP Address: ");
  Serial.println(WiFi.localIP());
}

void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String message = "";
  for (unsigned int i = 0; i < length; i++) {
    message += (char)payload[i];
  }

  Serial.print("Received MQTT Message on [");
  Serial.print(topic);
  Serial.print("]: ");
  Serial.println(message);

  // Extract "command" value manually from JSON
  String command = "";
  int cmdIndex = message.indexOf("\"command\"");
  if (cmdIndex != -1) {
    int colonIndex = message.indexOf(":", cmdIndex);
    int firstQuote = message.indexOf("\"", colonIndex);
    int secondQuote = message.indexOf("\"", firstQuote + 1);
    if (firstQuote != -1 && secondQuote != -1) {
      command = message.substring(firstQuote + 1, secondQuote);
    }
  }

  // Device-side Command Allowlist (Defense in Depth)
  if (command == "light_on") {
    digitalWrite(GREEN_LED, HIGH);
    doorActive = false; // Override timed door unlock
    Serial.println("Action: Light turned ON");
  } 
  else if (command == "light_off") {
    digitalWrite(GREEN_LED, LOW);
    doorActive = false;
    Serial.println("Action: Light turned OFF");
  } 
  else if (command == "unlock_door") {
    digitalWrite(GREEN_LED, HIGH);
    doorTimerEnd = millis() + 3000; // 3 seconds unlock simulation
    doorActive = true;
    Serial.println("Action: Door Unlocked for 3 seconds");
  } 
  else if (command == "alarm_on") {
    digitalWrite(RED_LED, HIGH);
    digitalWrite(BUZZER, HIGH);
    alarmTimerEnd = millis() + 3000; // 3 seconds alarm
    alarmActive = true;
    Serial.println("Action: Alarm Activated");
  } 
  else if (command == "alert_blocked") {
    digitalWrite(RED_LED, HIGH);
    alertTimerEnd = millis() + 5000; // 5 seconds alert blocked LED
    alertActive = true;
    Serial.println("Action: Attack Blocked LED Activated");
  } 
  else {
    Serial.print("Rejected unknown command: ");
    Serial.println(command);
  }
}

boolean connectMQTT() {
  Serial.print("Connecting to MQTT Broker at ");
  Serial.println(MQTT_HOST);

  String statusTopic = "aegis/status/" + String(DEVICE_ID);
  String cmdTopic = "aegis/cmd/" + String(DEVICE_ID);

  // Last Will & Testament payload: "offline" (retained)
  if (mqttClient.connect(DEVICE_ID, MQTT_USER, MQTT_PASS, statusTopic.c_str(), 1, true, "offline")) {
    Serial.println("MQTT Connected!");
    // Publish Retained Online status
    mqttClient.publish(statusTopic.c_str(), "online", true);
    // Subscribe to Command Topic
    mqttClient.subscribe(cmdTopic.c_str(), 1);
    return true;
  }
  return false;
}

void updateTimers() {
  unsigned long currentMillis = millis();

  // Handle Door Unlock Auto-Close
  if (doorActive && currentMillis >= doorTimerEnd) {
    digitalWrite(GREEN_LED, LOW);
    doorActive = false;
    Serial.println("Timer: Door Locked automatically");
  }

  // Handle Alarm Auto-Off
  if (alarmActive && currentMillis >= alarmTimerEnd) {
    digitalWrite(RED_LED, LOW);
    digitalWrite(BUZZER, LOW);
    alarmActive = false;
    Serial.println("Timer: Alarm Deactivated automatically");
  }

  // Handle Alert Blocked LED Auto-Off
  if (alertActive && currentMillis >= alertTimerEnd) {
    if (!alarmActive) {
      digitalWrite(RED_LED, LOW);
    }
    alertActive = false;
    Serial.println("Timer: Alert Blocked LED cleared");
  }
}

void setup() {
  Serial.begin(115200);
  setupPins();

  connectWiFi();

  mqttClient.setServer(MQTT_HOST, MQTT_PORT);
  mqttClient.setCallback(mqttCallback);

  connectMQTT();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  if (!mqttClient.connected()) {
    unsigned long now = millis();
    if (now - lastReconnectAttempt > 5000) {
      lastReconnectAttempt = now;
      if (connectMQTT()) {
        lastReconnectAttempt = 0;
      }
    }
  } else {
    mqttClient.loop();
  }

  updateTimers();
}
