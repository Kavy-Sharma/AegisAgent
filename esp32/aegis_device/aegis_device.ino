#include <WiFi.h>
#include <PubSubClient.h>
#include "secrets.h"

const char* DEVICE_ID    = "esp32-01";
const char* CMD_TOPIC    = "aegis/cmd/esp32-01";
const char* STATUS_TOPIC = "aegis/status/esp32-01";
const char* EVENT_TOPIC  = "aegis/status/esp32-01/event";

const int GREEN_LED  = 26;
const int RED_LED    = 27;
const int BUZZER     = 25;
const int YELLOW_LED = 14;   // optional extra

WiFiClient espClient;
PubSubClient mqtt(espClient);

bool greenTimed = false;  unsigned long greenStart = 0, greenDur = 0;
bool redTimed = false;    unsigned long redStart = 0,   redDur = 0;
bool yellowTimed = false; unsigned long yellowStart = 0;
bool alarmActive = false; unsigned long alarmStart = 0;

unsigned long lastWifiTry = 0, lastMqttTry = 0;
bool wasWifi = false;

void event(const char* msg) {
  Serial.print("EVENT: "); Serial.println(msg);
  if (mqtt.connected()) mqtt.publish(EVENT_TOPIC, msg, false);
}

void yellowPulse() {
  digitalWrite(YELLOW_LED, HIGH);
  yellowTimed = true;
  yellowStart = millis();
}

String getCommand(const String& m) {
  int k = m.indexOf("\"command\"");
  if (k < 0) return "";
  int c = m.indexOf(':', k + 9);
  if (c < 0) return "";
  int q1 = m.indexOf('"', c + 1);
  if (q1 < 0) return "";
  int q2 = m.indexOf('"', q1 + 1);
  if (q2 < 0) return "";
  return m.substring(q1 + 1, q2);
}

void handleCommand(const String& cmd) {
  if (cmd == "light_on") {
    digitalWrite(GREEN_LED, HIGH); greenTimed = false;
    yellowPulse(); event("light_on_done");
  } else if (cmd == "light_off") {
    digitalWrite(GREEN_LED, LOW); greenTimed = false;
    yellowPulse(); event("light_off_done");
  } else if (cmd == "unlock_door") {
    digitalWrite(GREEN_LED, HIGH);
    greenTimed = true; greenStart = millis(); greenDur = 3000;
    yellowPulse(); event("door_unlocked");
  } else if (cmd == "alarm_on") {
    alarmActive = true; alarmStart = millis();
    event("alarm_started");
  } else if (cmd == "alert_blocked") {
    digitalWrite(RED_LED, HIGH);
    redTimed = true; redStart = millis(); redDur = 5000;
    event("alert_blocked_shown");
  } else {
    Serial.println("IGNORED: unknown or empty command");
  }
}

void onMessage(char* topic, byte* payload, unsigned int length) {
  Serial.print("MSG on "); Serial.println(topic);
  if (length > 256) { Serial.println("IGNORED: too long"); return; }
  String m;
  for (unsigned int i = 0; i < length; i++) m += (char)payload[i];
  Serial.println(m);
  String cmd = getCommand(m);
  Serial.print("Command: "); Serial.println(cmd);
  handleCommand(cmd);
}

void updateHardware() {
  unsigned long now = millis();
  if (greenTimed && now - greenStart >= greenDur) {
    digitalWrite(GREEN_LED, LOW); greenTimed = false;
    event("door_locked");
  }
  if (redTimed && now - redStart >= redDur) {
    digitalWrite(RED_LED, LOW); redTimed = false;
  }
  if (alarmActive) {
    unsigned long el = now - alarmStart;
    if (el < 3000) {
      bool on = ((el / 250) % 2 == 0);
      digitalWrite(BUZZER, on);
      digitalWrite(YELLOW_LED, on);
    } else {
      digitalWrite(BUZZER, LOW);
      digitalWrite(YELLOW_LED, LOW);
      alarmActive = false;
      event("alarm_finished");
    }
  } else if (yellowTimed && now - yellowStart >= 300) {
    digitalWrite(YELLOW_LED, LOW); yellowTimed = false;
  }
}

void ensureWifi() {
  if (WiFi.status() == WL_CONNECTED) {
    if (!wasWifi) {
      wasWifi = true;
      Serial.print("Wi-Fi OK, ESP32 IP: ");
      Serial.println(WiFi.localIP());
    }
    return;
  }
  wasWifi = false;
  if (millis() - lastWifiTry >= 10000) {
    lastWifiTry = millis();
    Serial.println("Wi-Fi connecting...");
    WiFi.disconnect();
    WiFi.begin(WIFI_SSID, WIFI_PASS);
  }
}

void ensureMqtt() {
  if (WiFi.status() != WL_CONNECTED || mqtt.connected()) return;
  if (millis() - lastMqttTry < 5000) return;
  lastMqttTry = millis();
  Serial.println("MQTT connecting...");
  if (mqtt.connect(DEVICE_ID, MQTT_USER, MQTT_PASS,
                   STATUS_TOPIC, 0, true, "offline")) {
    Serial.println("MQTT connected");
    mqtt.subscribe(CMD_TOPIC);
    mqtt.publish(STATUS_TOPIC, "online", true);
    Serial.println("Subscribed + published online");
  } else {
    Serial.print("MQTT failed, state = ");
    Serial.println(mqtt.state());
  }
}

void setup() {
  Serial.begin(115200);
  pinMode(GREEN_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(BUZZER, OUTPUT);
  pinMode(YELLOW_LED, OUTPUT);
  digitalWrite(GREEN_LED, LOW);
  digitalWrite(RED_LED, LOW);
  digitalWrite(BUZZER, LOW);
  digitalWrite(YELLOW_LED, LOW);
  Serial.println("\nAEGISAGENT DEVICE starting");
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  lastWifiTry = millis();
  mqtt.setServer(MQTT_HOST, MQTT_PORT);
  mqtt.setCallback(onMessage);
}

void loop() {
  ensureWifi();
  ensureMqtt();
  mqtt.loop();
  updateHardware();
}