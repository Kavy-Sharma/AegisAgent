const int GREEN_LED = 26;
const int YELLOW_LED = 14;
const int RED_LED = 27;
const int BUZZER = 25;

void setup() {
  Serial.begin(115200);

  pinMode(GREEN_LED, OUTPUT);
  pinMode(YELLOW_LED, OUTPUT);
  pinMode(RED_LED, OUTPUT);
  pinMode(BUZZER, OUTPUT);

  digitalWrite(GREEN_LED, LOW);
  digitalWrite(YELLOW_LED, LOW);
  digitalWrite(RED_LED, LOW);
  digitalWrite(BUZZER, LOW);

  Serial.println("================================");
  Serial.println(" AEGISAGENT HARDWARE TEST");
  Serial.println("================================");
}

void loop() {

  // TEST 1: GREEN LED
  Serial.println("TEST 1: GREEN LED");
  digitalWrite(GREEN_LED, HIGH);
  delay(2000);
  digitalWrite(GREEN_LED, LOW);
  delay(500);

  // TEST 2: YELLOW LED
  Serial.println("TEST 2: YELLOW LED");
  digitalWrite(YELLOW_LED, HIGH);
  delay(2000);
  digitalWrite(YELLOW_LED, LOW);
  delay(500);

  // TEST 3: RED LED
  Serial.println("TEST 3: RED LED");
  digitalWrite(RED_LED, HIGH);
  delay(2000);
  digitalWrite(RED_LED, LOW);
  delay(500);

  // TEST 4: BUZZER
  Serial.println("TEST 4: BUZZER");
  digitalWrite(BUZZER, HIGH);
  delay(2000);
  digitalWrite(BUZZER, LOW);
  delay(1000);

  Serial.println("================================");
  Serial.println("ALL HARDWARE TESTS COMPLETED");
  Serial.println("================================");

  delay(2000);
}