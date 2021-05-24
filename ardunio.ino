// Maximum GPIO pin number
#define MAX_PIN 13

// Times to reset the GPIO value (INPUT)
unsigned long reset[MAX_PIN+1];

void setup() {
  // Reset the initial values for all pins
  for (int pin = 0; pin <= MAX_PIN; pin++) {
      pinMode(pin, INPUT);
      reset[pin] = 0;
  }
  // Setup the serial communication
  Serial.begin(115200);
  Serial.setTimeout(1);
  // Make sure millis() isn't 0
  delay(1);
}

void loop() {
  unsigned long current = millis();
  // If there's (at least) a pending byte, read it
  if (Serial.available() > 0) {
    byte pin = Serial.read();
    if (pin <= MAX_PIN) {
      // The pin should be reset back to INPUT after 10 milliseconds
      pinMode(pin, OUTPUT);
      reset[pin] = current + 10;
    }
  }
  // Check any pins have surpassed the reset time
  for (int pin = 0; pin <= MAX_PIN; pin++) {
    if (reset[pin] < current && reset[pin] != 0) {
      pinMode(pin, INPUT);
      reset[pin] = 0;
    }
  }
}
