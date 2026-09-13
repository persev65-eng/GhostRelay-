// =====================================================================
//  GhostRelay - Firmware ESP32 DevKit V1 + Ebyte E80-900M2212S (LR2021)
// =====================================================================
//
//  O ESP32 é a ponte entre o mac.py e o rádio. Ele não conhece o
//  protocolo GhostRelay: não faz hash, não assina, não sabe o que é
//  lista corrida. Ele só escuta, transmite e informa com que
//  parâmetros cada coisa aconteceu.
//
//
//  O QUE FALTAVA PARA O PROTOCOLO FUNCIONAR
//  ----------------------------------------
//
//  1) CAD - seção 3.1 ("escuta obrigatória antes de transmitir")
//
//     Não existia comando nenhum de sondagem do canal. O nó não tinha
//     como saber se alguém já estava no ar, então falava por cima.
//     Agora existe o comando CAD.
//
//  2) SET_CR / CONFIG - seção 21
//
//     Havia SET_SF e SET_BW, mas não SET_CR. A seção 21 exige
//     retransmitir com o MESMO SF, BW *e CR* escutados; sem controlar o
//     CR, a recompensa nunca seria concedida. Agora existe SET_CR e o
//     comando CONFIG, que ajusta os três de uma vez.
//
//  3) PARÂMETROS DE CADA PACOTE - seção 21
//
//     O firmware entregava só "MSG:<texto>". O PC não tinha como saber
//     com que SF/BW/CR aquilo chegou, e é exatamente isso que a seção
//     21 manda repetir na retransmissão. Agora a linha carrega os
//     parâmetros e o RSSI/SNR junto, numa linha só (sem risco de outro
//     evento entrar no meio).
//
//  4) COLISÃO x TRANSMISSÃO VÁLIDA - seção 3.3
//
//     Pacote com CRC errado era descartado em silêncio. A seção 3.3
//     trata colisão de forma diferente de transmissão válida: colisão é
//     ignorada, transmissão válida faz o nó perder a disputa. Sem
//     EVENT:CRC_ERROR o MAC não conseguia separar as duas.
//
//
//  BUGS CORRIGIDOS
//  ---------------
//
//  5) aplicarConfig() deixava o rádio SURDO.
//
//     Ela dava standby() e reinicializava, mas nunca voltava para
//     recepção. Depois de qualquer SET_* o nó parava de ouvir os
//     vizinhos até alguém mandar RX_START. Agora a recepção é
//     restaurada sozinha.
//
//  6) aplicarConfig() chamava radio.begin() de novo a cada ajuste,
//     reinicializando o chip inteiro para mudar um parâmetro. Agora usa
//     os setters, que é o caminho normal e muito mais rápido.
//
//  7) Serial.readStringUntil() BLOQUEAVA o loop.
//
//     Enquanto lia um comando, verificarRX() não rodava. Com timeout de
//     20 ms, comando longo ainda podia ser cortado no meio. Agora a
//     leitura é acumulada byte a byte, sem bloquear.
//
//     Junto: o buffer de recepção da serial do ESP32 tem 256 bytes por
//     padrão, e "TX " + 255 caracteres + "\n" dá 259. Ou seja, o
//     pacote máximo estourava o buffer. Agora o buffer é de 1024.
//
//  8) O eco EVENT:CMD_RECEIVED: era emitido até para TX, devolvendo o
//     pacote inteiro pela serial justamente no momento mais crítico.
//     O TX não ecoa mais o payload.
//
//
//  PINAGEM (conforme o documento do projeto)
//    NSS 5 | BUSY 4 | RESET 21 | DIO5 33 | SCK 18 | MISO 19 | MOSI 23
//
//  ATENÇÃO: nunca transmita sem antena conectada - o amplificador do
//  módulo pode ser danificado. A faixa liberada no Brasil para este
//  tipo de uso é 902-907,5 e 915-928 MHz.
// =====================================================================

#include <Arduino.h>
#include <SPI.h>
#include <RadioLib.h>


// =====================================
// PINAGEM ESP32 + E80 LR2021
// =====================================

#define PIN_NSS     5
#define PIN_BUSY    4
#define PIN_RESET  21
#define PIN_DIO5   33

#define PIN_SCK    18
#define PIN_MISO   19
#define PIN_MOSI   23


// Limite de um pacote LoRa
#define MAX_PAYLOAD 255

// Tamanho do acumulador de comando: "TX " + payload + folga
#define MAX_COMANDO (MAX_PAYLOAD + 16)


SPIClass SPI_RADIO(VSPI);


SPISettings spiSettings(
  1000000,
  MSBFIRST,
  SPI_MODE0
);


LR2021 radio = new Module(
  PIN_NSS,
  PIN_DIO5,
  PIN_RESET,
  PIN_BUSY,
  SPI_RADIO,
  spiSettings
);


// =====================================
// CONFIG RADIO
// =====================================

float freq = 915.0;

float bw = 250.0;

int sf = 12;

int cr = 7;          // 5..8  ->  4/5 .. 4/8

int power = 22;

int preambulo = 8;

int syncWord = 0x12;


bool rxAtivo = false;

// Flag de interrupcao de recepcao RadioLib
volatile bool pacoteRecebido = false;

void IRAM_ATTR callbackRX()
{
  pacoteRecebido = true;
}


// Acumulador de comando (leitura nao bloqueante)
String entrada = "";


// =====================================
// ESTADO DIAGNOSTICO
// =====================================

bool testeTX = false;

bool testeRX = false;


// =====================================
// VALIDACAO DE PARAMETROS
// =====================================

bool validarSF(int valor)
{
  return valor >= 5 && valor <= 12;
}


bool validarCR(int valor)
{
  // RadioLib usa o denominador: 5 = 4/5, 8 = 4/8
  return valor >= 5 && valor <= 8;
}


bool validarBW(float valor)
{
  return valor >= 7.8 && valor <= 500.0;
}


bool validarFreq(float valor)
{
  return valor >= 150.0 && valor <= 960.0;
}


// =====================================
// INICIAR RADIO
// =====================================

int iniciarRadio()
{
  int state = radio.begin(
    freq,
    bw,
    sf,
    cr,
    syncWord,
    power,
    preambulo
  );

  if(state == RADIOLIB_ERR_NONE)
  {
    radio.setPacketReceivedAction(callbackRX);
  }

  return state;
}


// =====================================
// RX
// =====================================

void iniciarRX()
{
  radio.standby();

  int state = radio.startReceive();

  if(state == RADIOLIB_ERR_NONE)
  {
    rxAtivo = true;

    Serial.println("EVENT:RX_STARTED");
  }
  else
  {
    rxAtivo = false;

    Serial.print("EVENT:RX_ERROR:");
    Serial.println(state);
  }
}


// =====================================
// RECEPÇÃO
// =====================================

void verificarRX()
{
  if(!rxAtivo)
    return;

  if(!pacoteRecebido)
    return;

  pacoteRecebido = false;

  String mensagem;

  int state = radio.readData(mensagem);


  if(state == RADIOLIB_ERR_NONE)
  {
    // O pacote do GhostRelay é texto. Caractere de controle dentro
    // dele quebraria o protocolo de linha da serial e faria o PC ler
    // meia mensagem como se fosse inteira.
    bool limpo = mensagem.length() > 0;

    for(unsigned int i = 0; i < mensagem.length(); i++)
    {
      if((unsigned char)mensagem[i] < 32)
      {
        limpo = false;
        break;
      }
    }

    if(!limpo)
    {
      Serial.println("EVENT:RX_DISCARDED:CTRL");
    }
    else
    {
      float rssi = radio.getRSSI();
      float snr  = radio.getSNR();

      // EVENT:RX primeiro - é ele que o MAC usa para saber que ouviu
      // uma transmissão válida e perdeu a disputa (seção 3.2)
      Serial.println("EVENT:RX");

      // Uma linha só: o pacote e os parâmetros com que ele chegou.
      // O MAC lê os campos de trás para frente, então '|' dentro da
      // mensagem do usuário não atrapalha.
      Serial.print("MSG:");
      Serial.print(mensagem);
      Serial.print("|SF=");   Serial.print(sf);
      Serial.print("|BW=");   Serial.print(bw, 1);
      Serial.print("|CR=");   Serial.print(cr);
      Serial.print("|RSSI="); Serial.print(rssi, 1);
      Serial.print("|SNR=");  Serial.println(snr, 1);

      if(testeRX)
      {
        Serial.println("EVENT:TEST_RX_OK");

        testeRX = false;
      }
    }
  }
  else if(state == RADIOLIB_ERR_CRC_MISMATCH)
  {
    // Seção 3.3 - COLISÃO. O nó não reage: só quem ele consegue
    // decodificar faz ele perder a disputa.
    Serial.println("EVENT:CRC_ERROR");
  }
  else
  {
    Serial.print("EVENT:RX_ERROR:");
    Serial.println(state);
  }

  // volta a escutar; se falhar, rxAtivo é corrigido
  int voltou = radio.startReceive();

  if(voltou != RADIOLIB_ERR_NONE)
  {
    rxAtivo = false;

    Serial.print("EVENT:RX_ERROR:");
    Serial.println(voltou);
  }
}


// =====================================
// TRANSMISSÃO
// =====================================

void transmitir(String msg)
{
  if(msg.length() == 0)
  {
    Serial.println("EVENT:TX_ERROR:VAZIO");
    return;
  }

  if(msg.length() > MAX_PAYLOAD)
  {
    // antes isso virava uma falha silenciosa do rádio
    Serial.print("EVENT:TX_ERROR:GRANDE:");
    Serial.println(msg.length());
    return;
  }

  bool voltarParaRX = rxAtivo;

  rxAtivo = false;

  radio.standby();

  Serial.println("EVENT:TX_START");

  int state = radio.transmit(msg);

  if(state == RADIOLIB_ERR_NONE)
  {
    Serial.println("EVENT:TX_OK");

    if(testeTX)
    {
      Serial.println("EVENT:TEST_TX_OK");

      testeTX = false;
    }
  }
  else
  {
    Serial.print("EVENT:TX_ERROR:");
    Serial.println(state);
  }

  delay(5);

  // só volta a escutar se estava escutando antes
  if(voltarParaRX)
    iniciarRX();
}


// =====================================
// CAD - ESCUTA ANTES DE TRANSMITIR (SEÇÃO 3.1)
// =====================================

void detectarCanal()
{
  bool voltarParaRX = rxAtivo;

  rxAtivo = false;

  radio.standby();

  int state = radio.scanChannel();

  if(state == RADIOLIB_CHANNEL_FREE)
  {
    Serial.println("EVENT:CAD_FREE");
  }
  else if(state >= 0)
  {
    // qualquer deteccao positiva: preambulo ou sinal LoRa no ar
    Serial.println("EVENT:CAD_BUSY");
  }
  else
  {
    // RadioLib sem suporte a CAD nesta versão/chip.
    // O MAC entende este evento e passa a operar sem escuta prévia.
    Serial.print("EVENT:CAD_UNSUPPORTED:");
    Serial.println(state);
  }

  if(voltarParaRX)
    iniciarRX();
}


// =====================================
// APLICAR CONFIGURAÇÃO
// =====================================

bool aplicarConfig()
{
  bool voltarParaRX = rxAtivo;

  rxAtivo = false;

  radio.standby();

  // Antes aqui havia um radio.begin() inteiro só para mudar um
  // parâmetro. Os setters fazem o mesmo sem reinicializar o chip.
  int erro = RADIOLIB_ERR_NONE;

  int e = radio.setFrequency(freq);
  if(e != RADIOLIB_ERR_NONE) erro = e;

  e = radio.setBandwidth(bw);
  if(e != RADIOLIB_ERR_NONE) erro = e;

  e = radio.setSpreadingFactor(sf);
  if(e != RADIOLIB_ERR_NONE) erro = e;

  e = radio.setCodingRate(cr);
  if(e != RADIOLIB_ERR_NONE) erro = e;

  e = radio.setOutputPower(power);
  if(e != RADIOLIB_ERR_NONE) erro = e;

  if(erro != RADIOLIB_ERR_NONE)
  {
    Serial.print("EVENT:CONFIG_ERROR:");
    Serial.println(erro);
  }

  // BUG ANTIGO: sem isto o rádio ficava em standby e o nó ficava
  // surdo até alguém mandar RX_START
  if(voltarParaRX)
    iniciarRX();

  return erro == RADIOLIB_ERR_NONE;
}


// =====================================
// CONFIG SF=12 BW=250 CR=7 [FREQ=915.0] [PWR=22]
// =====================================

int extrairInt(String s, const char *chave, int atual)
{
  int i = s.indexOf(chave);

  if(i < 0)
    return atual;

  return s.substring(i + strlen(chave)).toInt();
}


float extrairFloat(String s, const char *chave, float atual)
{
  int i = s.indexOf(chave);

  if(i < 0)
    return atual;

  return s.substring(i + strlen(chave)).toFloat();
}


void comandoConfig(String args)
{
  args.toUpperCase();

  int   novoSF   = extrairInt(args,   "SF=",   sf);
  int   novoCR   = extrairInt(args,   "CR=",   cr);
  float novoBW   = extrairFloat(args, "BW=",   bw);
  float novaFreq = extrairFloat(args, "FREQ=", freq);
  int   novoPWR  = extrairInt(args,   "PWR=",  power);

  if(!validarSF(novoSF))
  {
    Serial.println("EVENT:CONFIG_ERROR:SF");
    return;
  }

  if(!validarCR(novoCR))
  {
    Serial.println("EVENT:CONFIG_ERROR:CR");
    return;
  }

  if(!validarBW(novoBW))
  {
    Serial.println("EVENT:CONFIG_ERROR:BW");
    return;
  }

  if(!validarFreq(novaFreq))
  {
    Serial.println("EVENT:CONFIG_ERROR:FREQ");
    return;
  }

  sf    = novoSF;
  cr    = novoCR;
  bw    = novoBW;
  freq  = novaFreq;
  power = novoPWR;

  if(aplicarConfig())
  {
    Serial.println("EVENT:CONFIG_OK");
  }
}


// =====================================
// STATUS
// =====================================

void statusRadio()
{
  Serial.println("EVENT:STATUS");

  Serial.print("FREQ:");   Serial.println(freq, 3);
  Serial.print("BW:");     Serial.println(bw, 1);
  Serial.print("SF:");     Serial.println(sf);
  Serial.print("CR:");     Serial.println(cr);
  Serial.print("POWER:");  Serial.println(power);
  Serial.print("RX:");     Serial.println(rxAtivo ? 1 : 0);
}


// =====================================
// DIAGNOSTICO COMPLETO
// =====================================

void diagnostico()
{
  Serial.println("EVENT:DIAG_START");

  delay(100);

  // SPI já respondeu se chegou até aqui
  Serial.println("SPI:OK");

  int state = iniciarRadio();

  if(state == RADIOLIB_ERR_NONE)
  {
    Serial.println("RADIO:OK");
  }
  else
  {
    Serial.print("RADIO:ERROR:");
    Serial.println(state);

    return;
  }

  statusRadio();

  Serial.println("EVENT:DIAG_OK");

  // o diagnóstico reinicializa o rádio: sem isto o nó ficava surdo
  iniciarRX();
}


// =====================================
// COMANDOS SERIAL
// =====================================

void comando(String cmd)
{
  cmd.trim();

  if(cmd.length() == 0)
    return;

  // O TX não ecoa: o payload pode ter 255 caracteres e devolvê-lo pela
  // serial atrasaria justamente o momento mais crítico.
  if(!cmd.startsWith("TX "))
  {
    Serial.print("EVENT:CMD_RECEIVED:");
    Serial.println(cmd);
  }


  if(cmd.startsWith("TX "))
  {
    transmitir(cmd.substring(3));
  }

  else if(cmd == "RX_START")
  {
    iniciarRX();
  }

  else if(cmd == "RX_STOP")
  {
    rxAtivo = false;

    radio.standby();

    Serial.println("EVENT:RX_STOPPED");
  }

  else if(cmd == "CAD")
  {
    detectarCanal();
  }

  else if(cmd.startsWith("CONFIG"))
  {
    comandoConfig(cmd.substring(6));
  }

  else if(cmd == "STATUS")
  {
    statusRadio();
  }

  else if(cmd == "PING")
  {
    Serial.println("EVENT:PONG");
  }

  else if(cmd == "DIAG")
  {
    diagnostico();
  }

  else if(cmd == "TEST_TX")
  {
    testeTX = true;

    transmitir("GHOST_TEST_PACKET");
  }

  else if(cmd == "TEST_RX")
  {
    testeRX = true;

    iniciarRX();

    Serial.println("EVENT:TEST_RX_WAIT");
  }

  else if(cmd.startsWith("SET_FREQ "))
  {
    float valor = cmd.substring(9).toFloat();

    if(!validarFreq(valor))
    {
      Serial.println("EVENT:CONFIG_ERROR:FREQ");
      return;
    }

    freq = valor;

    if(aplicarConfig())
      Serial.println("EVENT:RADIO_OK");
  }

  else if(cmd.startsWith("SET_BW "))
  {
    float valor = cmd.substring(7).toFloat();

    if(!validarBW(valor))
    {
      Serial.println("EVENT:CONFIG_ERROR:BW");
      return;
    }

    bw = valor;

    if(aplicarConfig())
      Serial.println("EVENT:RADIO_OK");
  }

  else if(cmd.startsWith("SET_SF "))
  {
    int valor = cmd.substring(7).toInt();

    if(!validarSF(valor))
    {
      Serial.println("EVENT:CONFIG_ERROR:SF");
      return;
    }

    sf = valor;

    if(aplicarConfig())
      Serial.println("EVENT:RADIO_OK");
  }

  // faltava no firmware antigo: sem ele a seção 21 não fecha
  else if(cmd.startsWith("SET_CR "))
  {
    int valor = cmd.substring(7).toInt();

    if(!validarCR(valor))
    {
      Serial.println("EVENT:CONFIG_ERROR:CR");
      return;
    }

    cr = valor;

    if(aplicarConfig())
      Serial.println("EVENT:RADIO_OK");
  }

  else
  {
    // silêncio não deixava distinguir "comando inexistente" de
    // "firmware travado"
    Serial.print("EVENT:CMD_UNKNOWN:");
    Serial.println(cmd);
  }
}


// =====================================
// SETUP
// =====================================

void setup()
{
  // "TX " + 255 caracteres + "\n" dá 259 bytes: não cabe no buffer
  // padrão de 256. Tem que ser antes do begin().
  Serial.setRxBufferSize(1024);

  Serial.begin(115200);

  delay(1500);

  Serial.println("EVENT:BOOT");

  SPI_RADIO.begin(
    PIN_SCK,
    PIN_MISO,
    PIN_MOSI,
    PIN_NSS
  );

  int state = iniciarRadio();

  if(state == RADIOLIB_ERR_NONE)
  {
    Serial.println("EVENT:READY");

    iniciarRX();
  }
  else
  {
    Serial.print("EVENT:INIT_ERROR:");
    Serial.println(state);
  }
}


// =====================================
// LOOP
// =====================================

void loop()
{
  // Leitura não bloqueante: nunca perde o início de um pacote por
  // estar preso esperando o resto de um comando.
  while(Serial.available())
  {
    char c = (char)Serial.read();

    if(c == '\n' || c == '\r')
    {
      if(entrada.length() > 0)
      {
        comando(entrada);

        entrada = "";
      }
    }
    else
    {
      if(entrada.length() < MAX_COMANDO)
      {
        entrada += c;
      }
      else
      {
        // comando absurdo: descarta em vez de crescer sem limite
        entrada = "";

        Serial.println("EVENT:CMD_ERROR:GRANDE");
      }
    }
  }

  verificarRX();
}
