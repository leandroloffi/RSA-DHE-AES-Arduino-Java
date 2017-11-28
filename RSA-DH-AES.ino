#include <SPI.h>         // needed for Arduino versions later than 0018
#include <Ethernet.h>
#include <EthernetUdp.h>         // UDP library from: bjoern@cs.stanford.edu 12/30/2008
#include <math.h>
#include <string.h>
#include "AES.h"
#include "./printf.h"

AES aes;

// Enter a MAC address and IP address for your controller below.
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
// The IP address will be dependent on your local network:
IPAddress ip(150, 162, 63, 156);
IPAddress pc(150, 162, 63, 203);

int localPort = 8888;      // local port to listen on

// buffers for receiving and sending data
char packetBuffer[UDP_TX_PACKET_MAX_SIZE];  //buffer to hold incoming packet,
char  ReplyBuffer[38];//[] = "acknowledged";       // a string to send back
char  temp[38];
String replay;

int a = 2;
int g = 23;
int p = 86;

boolean clientHello = false;
boolean receivedRSAKey = false;
boolean receivedDiffieHellmanKey = false;

int my_pub = 9827;
int my_priv = 3786;
int java_pub;
int iv = 8;
int simpleKey = 0;
int simpleKeyServer = 0;

// An EthernetUDP instance to let us send and receive packets over UDP
EthernetUDP Udp;

void setup() {
  
  printf_begin();
  // start the Ethernet and UDP:
  Ethernet.begin(mac, ip);
  Udp.begin(localPort);
  Serial.begin(9600);
  Serial.println("********INICIO TROCA DE CHAVES********\n");
}

void receivesRSAKey() {
	
  int packetSize = Udp.parsePacket();

  if (packetSize) {
    Serial.println("*********RECEIVED RSA SERVER**********");  
    Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);

    /* Remove chave pública do Servidor do buffer. */
    int i = 0;
    char java_pub_string[32];
    while (packetBuffer[i] != '#') {
      java_pub_string[i] = packetBuffer[i];
      i++;
    }
    i++;
    java_pub = atoi(java_pub_string);
      
    /* Remove iv do buffer. */
    int iv_recebido;
    char iv_recebido_string[8];
    int j = 0;
    while (packetBuffer[i] != '\0') {
      iv_recebido_string[j] = packetBuffer[i];
      j++;
      i++;
    }
    iv_recebido = atoi(iv_recebido_string);

    
    Serial.print("RSA Public Key: ");
    Serial.println(java_pub);
    Serial.print("IV: ");
    Serial.println(iv_recebido);

    if ((iv_recebido-1) == iv){
      //Serial.println("O iv recebido está correto.");
      receivedRSAKey = true;
    }else{
      Serial.println("O iv recebido está incorreto.");
    } 
    // clear the char arrays for the next receive packet and send
    memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
    memset(packetBuffer, 0, sizeof(packetBuffer));
    delay(3000);
    Serial.println("**************************************\n");
  }
}

void sendsRSAKey() {
  Serial.println("************SEND RSA CLIENT***********");  
  char rsabuf[32];
  char ivbuf[8];

  sprintf(rsabuf, "%i", my_pub);
  sprintf(ivbuf, "%i", iv);

  /* Concatena chave pública, # e iv em rsabuf. */
  strcat(rsabuf, "#");
  strcat(rsabuf, ivbuf);
    
  /* Realiza envio da chave. */
  Udp.beginPacket(pc, localPort);
  Udp.write(rsabuf);
  Udp.endPacket();

  Serial.print("RSA Public Key: ");
  Serial.println(my_pub);
  Serial.print("IV: ");
  Serial.println(iv);
  Serial.println("**************************************\n");

  delay(3000);
}

void sendsDiffieHellmanKey() {
  /* Envio da primeira chave. */
  Serial.println("************SEND DH CLIENT************");  
  int aux = (int) pow(g, a);
  int envio = aux % p;
  char bufP[10];
  char bufG[10];
  char bufIv[10];
  char buf[32];

  /* Passa os valores p, g e iv para string. */  
  sprintf(bufP, "%i", p);
  sprintf(bufG, "%i", g);
  sprintf(bufIv, "%i", iv);
    
  sprintf(buf, "%i", envio);

  /* Concatena p, g e iv no buffer. */
  strcat(buf, "#");
  strcat(buf, bufP);
  strcat(buf, "#");
  strcat(buf, bufG);
  strcat(buf, "#");
  strcat(buf, bufIv);
    
  /* Realiza envio da chave. */
  Udp.beginPacket(pc, localPort);
  Udp.write(buf);
  Udp.endPacket();

  //Serial.println("*** Chave Diffie-Hellman enviada! ***");
  Serial.print("Diffie-Hellman Key: ");
  Serial.println(envio);
  Serial.print("p: ");
  Serial.println(bufP);
  Serial.print("g: ");
  Serial.println(bufG);
  Serial.print("IV: ");
  Serial.println(bufIv);
  Serial.println("**************************************\n");

  delay(3000);
}

void receivesDiffieHellmanKey() {
  int packetSize = Udp.parsePacket();
  /* Recebeu chave. */
  if (packetSize) {
    Serial.println("*********RECEIVED DH SERVER*********");
    Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
  
    /* Recupera chave do Servidor do buffer. */
    int value;
    char valueBuff[32] = {' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' '};
    char valueBuf[32] = {' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',' '};

    int i = 0;
    while (packetBuffer[i] != '#') {
      valueBuf[i] = packetBuffer[i];
      i++;
    }
    i++;

    value = atoi(valueBuf);
    int aux1 = (int) pow(value, a);
    simpleKeyServer = aux1 % p;
    //simpleKeyServer = value;
    Serial.print("Diffie-Hellman Key: ");
    Serial.println(value);

    int aux = (int) pow(value, a);
    simpleKey = aux % p;
      
    /* Remove iv do buffer. */
    int iv_recebidoDH;
    char iv_recebido_stringDH[8];
    int j = 0;
    while (packetBuffer[i] != '\0') {
      iv_recebido_stringDH[j] = packetBuffer[i];
      j++;
      i++;
    }
    iv_recebidoDH = atoi(iv_recebido_stringDH);

    
    Serial.print("IV: ");
    Serial.println(iv_recebidoDH);
    
    if ((iv_recebidoDH-1) == iv){
      //Serial.println("O iv recebido está correto.");
      receivedDiffieHellmanKey = true;
    }else{
      Serial.println("O iv recebido está incorreto.");
    }
    // clear the char arrays for the next receive packet and send
    memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
    memset(packetBuffer, 0, sizeof(packetBuffer));

    Serial.println("**************************************\n");
  
    Serial.println("***SYMMETRICAL SESSION CLIENT-SERVER***");
    Serial.print("Session Key: ");
    Serial.println(simpleKeyServer);
    delay(3000);
    Serial.println("**************************************\n");
  }
}

void sendClientHello(){
    char test[32];

    sprintf(test, "%s", "hello");
    Serial.println("************HELLO CLIENT**************");
    Serial.println("Hello Client: Successful");
    Udp.beginPacket(pc, localPort);
    Udp.write(test);
    Udp.endPacket();
    Serial.println("**************************************\n");
}

void receivesServerHello(){
    
    int packetSize = Udp.parsePacket();

    if (packetSize) {
      Serial.println("************HELLO SERVER**************");
      Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
      char recebido[32];
      if(packetBuffer[0]=='#'){
        Serial.println("Server Client: Successful");
        clientHello = true;
      }
      Serial.println("**************************************\n");
    }
        // clear the char arrays for the next receive packet and send
    memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
    memset(packetBuffer, 0, sizeof(packetBuffer));
}

void encryptAES (int bits, int cipher_size, byte *key, byte plain[], unsigned long long int my_iv){
  Serial.println("************AES ENCRYPT**************");
  aes.iv_inc();
  byte iv [N_BLOCK] ;
  byte plain_p[48];
  byte cipher [48] ;
  byte check [48] ;
  unsigned long ms = micros ();
  aes.set_IV(my_iv);
  aes.get_IV(iv);  
  aes.do_aes_encrypt(plain, cipher_size, cipher, key, bits, iv);
  Serial.print("Encryption took: ");
  Serial.println(micros() - ms);
  
  
  ms = micros ();
  aes.set_IV(my_iv);
  aes.get_IV(iv);
  int total = 16;
  if(cipher_size > 16 && cipher_size <= 32){
    total = 32;
  }else if(cipher_size > 32 && cipher_size <= 48){
    total = 48;
  }else if(cipher_size > 48 && cipher_size <= 64){
    total = 64;
  }
  aes.do_aes_decrypt(cipher, total, check, key, bits, iv);
  Serial.print("Decryption took: ");
  Serial.println(micros() - ms);/*
  printf("\n\nKEY   :");
  aes.printArray(key,(bool)false);*/
  printf("\n\nPLAIN :");
  aes.printArray(plain,(bool)true);
  printf("\nCIPHER:");
  aes.printArray(cipher,(bool)false);
  printf("\nCHECK :");
  aes.printArray(check,(bool)true);
  printf("\nIV    :");
  aes.printArray(iv,16);
  
  char bufAES[48];
  
  Udp.beginPacket(pc, localPort);
  Udp.write(bufAES);
  Udp.endPacket();
  
  delay(5000);
  Serial.println("**************************************\n");
}

void loop() {

  if(!clientHello){
    sendClientHello();
    Serial.println("--------Esperando Hello Server--------\n");
    while(clientHello!=true){
      receivesServerHello();
    }
  }

  /* Realiza a troca de chaves RSA. */
  if (clientHello && !receivedRSAKey) {
    sendsRSAKey();
    while(receivedRSAKey!=true){
      receivesRSAKey();
    }
  }

  /* Realiza a troca de chaves Diffie-Hellman sem criptografia. */
  if (receivedRSAKey && !receivedDiffieHellmanKey) {
    sendsDiffieHellmanKey();
    while(receivedDiffieHellmanKey!=true){
      receivesDiffieHellmanKey();
    }
  }
  
  /* Com as chaves trocadas, inicia a troca de dados. */
  if (receivedRSAKey && receivedDiffieHellmanKey) {
    uint8_t key[16];
    uint8_t iv[16];
    int j;
    for (j = 0; j < 16; j++) {
      key[j] = simpleKey;
      iv[j] = j+1;
    }
    const uint16_t data_len = 16;
    
  byte *key21 = (unsigned char*)"1234567891234567";

  byte plain1[] = "Segurança é muito importante para IoT!";
  
  unsigned long long int my_iv = iv;
    
    encryptAES(128, 41, key21, plain1, my_iv);
  }
}
