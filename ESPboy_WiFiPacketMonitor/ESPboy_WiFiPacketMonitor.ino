/*
WiFi packet monitor and deauth attack detector
Port of github.com/spacehuhn Packet Monitor for ESPboy project
www.esoboy.com
*/

/*
  ===========================================
       Copyright (c) 2018 Stefan Kremser
              github.com/spacehuhn
  ===========================================
*/

#include <ESP8266WiFi.h>
#include <Wire.h>
#include <ESP_EEPROM.h>

#include <TFT_eSPI.h>          //to draw at LCD TFT
#include <Adafruit_MCP23017.h> //to control buttons
#include <Adafruit_MCP4725.h>  //to control the LCD display backlit

#include "ESPboyLogo.h"
#include "ESPboyGUI.h"
#include "ESPboyOTA.h"
#include "ESPboy_LED.h"

#define PAD_LEFT        0x01
#define PAD_UP          0x02
#define PAD_DOWN        0x04
#define PAD_RIGHT       0x08
#define PAD_ACT         0x10
#define PAD_ESC         0x20
#define PAD_LFT         0x40
#define PAD_RGT         0x80
#define PAD_ANY         0xff

//PINS
#define LEDPIN         D4
#define SOUNDPIN       D3
#define LEDLOCK        9
#define CSTFTPIN       8 //Chip Select pin for LCD (it's on the MCP23017 GPIO expander GPIO8)

#define MCP23017address 0 // actually it's 0x20 but in <Adafruit_MCP23017.h> lib there is (x|0x20) :)
#define MCP4725address  0x60

Adafruit_MCP4725 dac;
Adafruit_MCP23017 mcp;
ESPboyLED myled;
TFT_eSPI tft;
ESPboyGUI* GUIobj = NULL;
ESPboyOTA* OTAobj = NULL;

#define maxCh 14       // max Channel -> US = 11, EU = 13, Japan = 14
#define packetRate 5   // min. packets before it gets recognized as an attack

/* Display settings */
#define minRow       0              /* default =   0 */
#define maxRow     127              /* default = 127 */
#define minLine      0              /* default =   0 */
#define maxLine    127             /* default =  63 */

/* render settings */
#define Row1         0
#define Row2        17
#define Row3        37
#define Row4        67
#define Row5        92
#define Row6       110

#define LineText     0
#define Line        12
#define LineVal     100

//===== Run-Time variables =====//
uint32_t prevTime    = 0;
uint32_t curTime     = 0;
uint32_t pkts        = 0;
uint32_t no_deauths  = 0;
uint32_t deauths     = 0;
uint8_t curChannel   = 1;
uint32_t maxVal      = 0;
double multiplicator = 0.0;

uint16_t val[128];


uint8_t getKeys() { return (~mcp.readGPIOAB() & 255); }

void sniffer(uint8_t *buf, uint16_t len) {
  pkts++;
  if (buf[12] == 0xA0 || buf[12] == 0xC0) {
    deauths++;
  }
}

void getMultiplicator() {
  maxVal = 1;
  for (uint8_t i = 0; i < maxRow; i++) {
    if (val[i] > maxVal) maxVal = val[i];
  }
  if (maxVal > LineVal) multiplicator = (double)LineVal / (double)maxVal;
  else multiplicator = 1;
}




void setup() {
  Serial.begin(115200); //serial init

//DAC init and backlit off
  dac.begin(MCP4725address);
  delay (100);
  dac.setVoltage(0, false);

//mcp23017 init for buttons, LED LOCK and TFT Chip Select pins
  mcp.begin(MCP23017address);
  delay(100);
  
  for (int i=0;i<8;i++){  
     mcp.pinMode(i, INPUT);
     mcp.pullUp(i, HIGH);}

//LED init
  mcp.pinMode(LEDLOCK, OUTPUT);
  mcp.digitalWrite(LEDLOCK, HIGH); 
  myled.begin();

//sound init and test
  pinMode(SOUNDPIN, OUTPUT);
  tone(SOUNDPIN, 200, 100); 
  delay(100);
  tone(SOUNDPIN, 100, 100);
  delay(100);
  noTone(SOUNDPIN);
  
//LCD TFT init
  mcp.pinMode(CSTFTPIN, OUTPUT);
  mcp.digitalWrite(CSTFTPIN, LOW);
  tft.begin();
  delay(100);
  tft.setRotation(0);
  tft.fillScreen(TFT_BLACK);

//draw ESPboylogo  
  tft.drawXBitmap(30, 24, ESPboyLogo, 68, 64, TFT_YELLOW);
  tft.setTextSize(1);
  tft.setTextColor(TFT_YELLOW);
  tft.setCursor(8,102);
  tft.print (F("WiFi packet monitor"));

//LCD backlit fading on
  for (uint16_t bcklt=0; bcklt<4095; bcklt+=20){
    dac.setVoltage(bcklt, false);
    delay(10);}

//clear TFT and backlit on high
  dac.setVoltage(4095, false);
  tft.fillScreen(TFT_BLACK);

//OTA init
  if (getKeys()){ 
    GUIobj = new ESPboyGUI(&tft, &mcp);
    OTAobj = new ESPboyOTA(GUIobj);}

//Init WiFi
  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  WiFi.disconnect();
  wifi_set_promiscuous_rx_cb(sniffer);
  wifi_set_channel(curChannel);
  wifi_promiscuous_enable(1);

  EEPROM.begin(10);
  curChannel = EEPROM.read(2);
  if (curChannel < 1 || curChannel > maxCh) {
    curChannel = 1;
    EEPROM.write(2, curChannel);
    EEPROM.commit();
  }

  tft.setTextColor(TFT_GREEN);
}



void loop() {
  curTime = millis();

  if(getKeys()){
    curChannel++;
    if (curChannel > maxCh) curChannel = 1;
    wifi_set_channel(curChannel);
    for (uint8_t i = 0; i < maxRow; i++) val[i] = 0;
      pkts = 0;
      multiplicator = 1;

    //save changes
      EEPROM.write(2, curChannel);
      EEPROM.commit();

      if (pkts == 0) pkts = deauths;
      no_deauths = pkts - deauths;

      prevTime = 0;
  }
      
  //every second
  if (curTime - prevTime >= 1000) {
    prevTime = curTime;

    //move every packet bar one pixel to the left
    for (uint8_t i = 0; i < maxRow; i++)
      val[i] = val[i + 1];
    val[127] = pkts;

    //recalculate scaling factor
    getMultiplicator();

    //deauth alarm
    if (deauths > packetRate) {
      myled.setRGB (5, 0, 0); 
      tone(SOUNDPIN, 200, 10); 
      delay(1000);}
    else myled.setRGB (0, 5, 0);

    if (pkts == 0) pkts = deauths;
    no_deauths = pkts - deauths;

    //draw display
    tft.fillScreen(TFT_BLACK);
    tft.drawLine(minRow, Line, maxRow, Line, TFT_YELLOW);
    tft.drawString("Ch:", Row1, LineText);
    tft.drawString("Pkts:", Row3, LineText);
    tft.drawString("DA:", Row5, LineText);
    tft.drawString((String)curChannel, Row2, LineText);
    tft.drawString((String)no_deauths, Row4, LineText);
    tft.drawString((String)deauths, Row6, LineText);
    
    for (uint8_t i = 0; i < maxRow; i++) 
      tft.drawLine(i, maxLine, i, maxLine - val[i]*multiplicator, TFT_YELLOW);
    
    //reset counters
    deauths = 0;
    pkts = 0;
  }
  delay(150);
}
