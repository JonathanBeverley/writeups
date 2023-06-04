#include <Servo.h>
#include <Keypad.h>

Servo servo1;

const byte ROWS = 4;
const byte COLS = 3;

char hexaKeys[ROWS][COLS] = {
  {'1', '2', '3'},
  {'4', '5', '6'},
  {'7', '8', '9'},
  {'*', '0', '#'}
};

byte rowPins[ROWS] = {6, 7, 8, 9}; //connect to the row pinouts of the keypad
byte colPins[COLS] = {3, 4, 5}; //connect to the column pinouts of the keypad

Keypad customKeypad = Keypad(makeKeymap(hexaKeys), rowPins, colPins, ROWS, COLS);

int n = 0;
char d[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

void setup() {
  servo1.attach(11);
  /*Serial.begin(9600);
  Serial.println("Hello World!");*/
}

void loop() {
  // put your main code here, to run repeatedly:
  servo1.write(90);
  //servo1.write(servo);

  char customKey = customKeypad.getKey();

  if (customKey) {
    switch (customKey) {
      case '*':
      case '#':
        if (strcmp(d, "73452912") == 0 && n == 11) {
          servo1.write(0);
          delay(3000);
          servo1.write(90);

        }
        n = 0;
        for (int i = 0; i < 8; i++) {
          d[i] = 0;
        }
        break;

      default:
        d[n++ % 8] = customKey;
        break;
    }
  }
}
