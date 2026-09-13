#!/usr/bin/env python3

"""
GhostRelay - MAC + ponte serial com o ESP32

Responsabilidade:

- Acesso ao meio (seção 3)
- Conversa com o firmware pela serial
- Aplicar SF/BW/CR de cada pacote antes de transmitir (seção 21)
- Avisar as camadas de cima pela fila mac_events

Não controla:
- hash
- assinatura
- vizinhos
- lista corrida
- prioridade


SEÇÃO 3 - COMO ESTÁ IMPLEMENTADA
--------------------------------
 3.1  escuta obrigatória antes de transmitir  -> comando CAD
 3.2  janela aleatória 0..50 ms; ouvir transmissão válida congela a
      contagem, espera o canal liberar e sorteia de novo na metade
 3.3  transmitiu    -> janela dobra
      perdeu        -> janela divide por 2
      colisão (CRC) -> IGNORADA, a contagem continua
 3.4  o ciclo se repete indefinidamente


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) O NÓ NUNCA PERDIA UMA DISPUTA.

   canal_ocupado, tx_start_time, last_tx_time_ms, rx_start_time e
   last_rx_time_ms eram atribuídas dentro de Radio.receber() sem
   declaração global, então viravam variáveis locais da thread leitora.
   executar_backoff() lia as globais, que ficavam False para sempre.
   Resultado: as seções 3.2 e 3.3 não aconteciam, o nó nunca cedia o
   canal e nunca ajustava a janela. Agora o estado mora no objeto Radio,
   onde não tem como se perder.

2) NADA IA AO AR.

   transmitir() mandava json.dumps({"cmd":"TX",...}) para o ESP32, mas o
   firmware só entende "TX <texto>". O comando caía no vazio. Agora o
   MAC fala o protocolo de linha do firmware, e manda SF/BW/CR por
   comando de configuração ANTES do TX.

3) radio_config era usada e nunca existia. O NameError acontecia dentro
   do try da thread leitora e era engolido pelo except: mac_events nunca
   recebia TX_DONE e o main.py ficava esperando um evento que não vinha.

4) TODA MENSAGEM RECEBIDA ERA DESCARTADA.

   processar_rx fazia enviar_server("RX " + msg) com msg virando dict:
   TypeError a cada pacote, capturado por um except nu, em laço quente.
   Além disso mandava o pacote cru para a aplicação, pulando a
   verificação de assinatura (seção 15) e o cache (seção 6). Agora o
   pacote sobe como evento RX_DONE para o main.py decidir.

5) O TEMPO DE ANTENA ERA SEMPRE ZERO.

   rx_start_time só era marcado em EVENT:RX_PACKET_START, evento que o
   firmware nunca emite. Zero ms = zero ponto = seções 8, 17 e 20
   desligadas. Agora o tempo é calculado pelo economy.py a partir de
   tamanho + SF + BW + CR, que é determinístico e igual nos dois lados.

6) esperar_tx() não limpava tx_ok antes de transmitir: um TX_OK antigo
   fazia a transmissão seguinte "dar certo" instantaneamente.

7) O socket lia com recv() sem juntar linhas: dois comandos no mesmo
   pacote TCP viravam um só e se perdiam.

8) A janela dobrava sem teto. Depois de algumas transmissões seguidas o
   nó passaria minutos calado.


FIRMWARE
--------
Funciona com o firmware atual, mas com as limitações que ele impõe:

    CAD      -> não existe: sem escuta antes de transmitir (seção 3.1)
    SET_CR   -> não existe: não dá para casar o CR (seção 21)

O MAC detecta as duas coisas sozinho, avisa uma vez e segue no modo
degradado. Com o firmware corrigido (comandos CONFIG e CAD), as seções
3.1 e 21 passam a funcionar de verdade.
"""

import glob
import json
import os
import queue
import random
import socket
import threading
import time

try:

    import serial

except ImportError:

    raise ImportError(
        "GhostRelay precisa da biblioteca pyserial para falar com o ESP32.\n"
        "Instale com:  pip install pyserial"
    )

try:

    from economy import GhostEconomy

except Exception:

    GhostEconomy = None


# ===============================
# CONFIGURAÇÃO
# ===============================

SERIAL_PORT = "/dev/ttyACM0"

BAUD = 115200


SOCKET_HOST = "127.0.0.1"

SOCKET_PORT = 9000


# Configuração de escuta padrão do nó.
# O rádio só escuta um SF por vez: depois de transmitir com os
# parâmetros de uma mensagem (seção 21), ele volta para cá.
LISTEN_CONFIG = {

    "sf": 12,

    "bw": 250.0,

    "cr": 7

}


# LR2021 SF12 BW250: duração de um símbolo
SLOT_TIME = 0.016384


# Passo da contagem regressiva. O backoff é medido em ms, então contar
# de 16 em 16 ms (um símbolo) daria 2 ou 3 passos numa janela de 50 ms.
TICK = 0.001


# GhostRelay Backoff (seção 3.2)

BACKOFF_START = 50.0    # ms

BACKOFF_MIN = 5.0       # ms - piso, senão a janela vira zero

BACKOFF_MAX = 1600.0    # ms - teto, senão o nó dobra até nunca mais falar


# Tempos limite
TIMEOUT_TX = 30.0        # s  (SF12/BW250 com 255 bytes leva ~6 s no ar)
TIMEOUT_RADIO = 10.0     # s  esperando o rádio ficar pronto
TIMEOUT_CANAL = 15.0     # s  esperando o canal liberar
TIMEOUT_CAD = 2.0        # s  resposta do comando CAD
TIMEOUT_CONFIG = 3.0     # s  resposta do comando de configuração


# Limite de payload do LoRa
MAX_PAYLOAD = 255


# ===============================
# FILAS
# ===============================

tx_queue = queue.Queue()

rx_queue = queue.Queue(maxsize=200)

# Eventos internos para comunicação com economy.py,
# relay_queue.py e demais módulos
mac_events = queue.Queue(maxsize=500)

# Comandos futuros vindos da camada superior
mac_commands = queue.Queue()


server_socket = None

server_lock = threading.Lock()


encerrar = threading.Event()


# ===============================
# SERVER
# ===============================

def enviar_server(msg):

    global server_socket

    if isinstance(msg, dict):

        msg = json.dumps(msg)

    with server_lock:

        if server_socket:

            try:

                server_socket.sendall(
                    (str(msg) + "\n").encode()
                )

            except OSError:

                # conexão morta: solta a referência em vez de insistir
                server_socket = None


def publicar_evento(evento):
    """
    Entrega um evento para as camadas de cima.

    A fila é limitada: se ninguém estiver consumindo, o mais antigo sai.
    Evento acumulado sem limite come a memória do nó em poucas horas.
    """

    try:

        mac_events.put_nowait(evento)

    except queue.Full:

        try:

            mac_events.get_nowait()

            mac_events.put_nowait(evento)

        except queue.Empty:

            pass


# ===============================
# UTILIDADES
# ===============================

def detectar_porta():
    """
    Acha a porta do ESP32 sozinho, para não precisar editar o código
    a cada máquina diferente.
    """

    for padrao in ("/dev/ttyACM*", "/dev/ttyUSB*",
                   "/dev/cu.usbserial*", "/dev/cu.wchusbserial*",
                   "/dev/cu.SLAB*"):

        achados = sorted(glob.glob(padrao))

        if achados:

            return achados[0]

    return SERIAL_PORT


def _formatar_bw(bw):

    bw = float(bw)

    return str(int(bw)) if bw == int(bw) else str(bw)


def _numero(texto):

    try:

        return float(texto)

    except (TypeError, ValueError):

        return None


def normalizar_radio(radio):
    """
    Usa o normalizador do economy.py quando disponível
    (aceita 250/250.0/"250", e 7/"4/7"/47).
    """

    if GhostEconomy:

        return GhostEconomy.normalize_radio(radio)

    if not isinstance(radio, dict):

        return None

    if (radio.get("sf") is None
            or radio.get("bw") is None
            or radio.get("cr") is None):

        return None

    return {

        "sf": int(radio["sf"]),

        "bw": float(radio["bw"]),

        "cr": int(radio["cr"])

    }


def validar_config_radio(pacote):
    """
    Confere se um pacote possui
    configuração de rádio completa.

    Evita transmitir assumindo
    configuração antiga do ESP32.
    """

    if not isinstance(pacote, dict):

        return False

    return normalizar_radio(pacote) is not None


def normalizar_pacote(dados):
    """
    Normaliza pacotes recebidos da relay_queue.

    Formato:

    {
        packet:"",
        hash:"",
        sf:12,
        bw:250,
        cr:7
    }

    Mantém compatibilidade com mensagens antigas em texto: sem SF/BW/CR,
    assume a configuração de escuta do nó, que é o único palpite
    honesto possível.
    """

    if isinstance(dados, dict):

        return {

            "packet": dados.get("packet", ""),

            "hash": dados.get("hash"),

            "sf": dados.get("sf"),

            "bw": dados.get("bw"),

            "cr": dados.get("cr"),

            "type": dados.get("type", "MESSAGE")

        }

    return {

        "packet": str(dados),

        "hash": None,

        "sf": LISTEN_CONFIG["sf"],

        "bw": LISTEN_CONFIG["bw"],

        "cr": LISTEN_CONFIG["cr"],

        "type": "MESSAGE"

    }


# ===============================
# RADIO
# ===============================


class Radio:
    """
    Fala o protocolo de linha do firmware.

    ESP32 -> PC
        EVENT:BOOT | EVENT:READY | EVENT:RX_STARTED
        EVENT:RX                       pacote decodificado
        MSG:<pacote>                   conteúdo recebido
        MSG:<pacote>|SF=..|BW=..|CR=..|RSSI=..|SNR=..   (firmware novo)
        EVENT:CRC_ERROR                colisão - seção 3.3, ignorada
        EVENT:TX_START | EVENT:TX_OK | EVENT:TX_ERROR:<n>
        EVENT:CAD_FREE | EVENT:CAD_BUSY                 (firmware novo)
        EVENT:CONFIG_OK | EVENT:RADIO_OK

    PC -> ESP32
        RX_START | RX_STOP | STATUS | CAD
        CONFIG SF=<7..12> BW=<125|250|500> CR=<5..8>
        SET_SF <n> | SET_BW <n> | SET_CR <n>
        TX <pacote>

    Todo o estado fica aqui dentro, em atributos. Antes ele estava
    espalhado em variáveis de módulo que a thread leitora transformava
    em locais sem querer.
    """

    def __init__(self, port=None, baud=BAUD, listen_config=None):

        self.port = port or os.environ.get("GHOST_PORTA") or detectar_porta()

        self.listen_config = dict(listen_config or LISTEN_CONFIG)

        self.radio_config = dict(self.listen_config)

        print("[RADIO] conectando em", self.port)

        try:

            self.ser = serial.Serial(self.port, baud, timeout=0.2)

        except serial.SerialException as erro:

            print("[RADIO] nao consegui abrir a porta:", erro)

            print("        o diag.py ou o monitor serial da IDE estao abertos?")

            raise

        # abrir a serial reinicia o ESP32 (DTR): espera o boot
        time.sleep(3)

        # Limpa mensagens antigas do boot do ESP32
        self.ser.reset_input_buffer()

        # ------------- estado (antes eram globais que se perdiam) -----
        self.pronto = threading.Event()

        self.tx_ok = threading.Event()

        self.tx_erro = threading.Event()

        self.config_ok = threading.Event()

        # seção 3.2: ouvimos uma transmissão que deu para decodificar
        self.transmissao_valida = threading.Event()

        self.cad_resposta = queue.Queue()

        self.suporta_cad = None        # None = ainda não sei

        self.suporta_config = None

        self.avisou_cr = False

        self.ultimo_rssi = None

        self.ultimo_snr = None

        self.escrita_lock = threading.Lock()

        threading.Thread(

            target=self.receber,

            daemon=True,

            name="serial"

        ).start()

    # -----------------------------------------------------------------
    def enviar(self, cmd, silencioso=False):

        with self.escrita_lock:

            try:

                self.ser.write((cmd + "\n").encode("ascii", "ignore"))

                self.ser.flush()

            except serial.SerialException as erro:

                print("[RADIO] erro de escrita:", erro)

                encerrar.set()

                return False

        if not silencioso:

            print("[RADIO TX]", cmd)

        return True

    # -----------------------------------------------------------------
    def receber(self):

        while not encerrar.is_set():

            try:

                linha = self.ser.readline().decode("ascii", "ignore").strip()

            except serial.SerialException as erro:

                print("[RADIO] serial caiu:", erro)

                encerrar.set()

                return

            except Exception:

                time.sleep(0.05)

                continue

            if not linha:

                continue

            # O firmware ecoa todo comando recebido. Sem ignorar o eco,
            # "EVENT:CMD_RECEIVED:RX_START" era lido como evento de
            # verdade por qualquer parser que usasse "in".
            if linha.startswith("EVENT:CMD_RECEIVED"):

                continue

            print("[RADIO]", linha)

            try:

                self._tratar_linha(linha)

            except Exception as erro:

                # a thread leitora não pode morrer por causa de uma
                # linha estranha
                print("[RADIO] erro ao tratar linha:", erro)

    # -----------------------------------------------------------------
    def _tratar_linha(self, linha):

        if linha.startswith("MSG:"):

            self._tratar_pacote(linha[4:])

            return

        if not linha.startswith("EVENT:"):

            return

        evento = linha[6:]

        if evento in ("READY", "RX_STARTED", "RADIO_OK"):

            self.pronto.set()

            if evento == "RADIO_OK":

                self.config_ok.set()

        elif evento == "CONFIG_OK":

            self.config_ok.set()

        elif evento == "BOOT":

            print("[RADIO] o ESP32 reiniciou")

            self.pronto.clear()

        elif evento == "RX":

            # seção 3.2: transmissão que deu para decodificar.
            # É só isso que faz o nó perder a disputa.
            self.transmissao_valida.set()

        elif evento in ("CRC_ERROR", "RX_CRC_ERROR"):

            # seção 3.3: colisão é IGNORADA, a contagem continua
            pass

        elif evento == "TX_OK":

            self.tx_ok.set()

        elif evento.startswith("TX_ERROR"):

            self.tx_erro.set()

        elif evento == "CAD_FREE":

            self.cad_resposta.put(True)

        elif evento == "CAD_BUSY":

            self.cad_resposta.put(False)

        elif evento.startswith("CAD_UNSUPPORTED"):

            self.suporta_cad = False

            self.cad_resposta.put(True)

        elif evento.startswith("RSSI:"):

            self.ultimo_rssi = _numero(evento[5:])

        elif evento.startswith("SNR:"):

            self.ultimo_snr = _numero(evento[4:])

        elif evento.startswith(("INIT_ERROR", "RADIO_ERROR", "RX_ERROR")):

            print("[RADIO] FALHA:", linha)

    # -----------------------------------------------------------------
    def _separar_metadados(self, corpo):
        """
        O firmware novo manda MSG:<pacote>|SF=..|BW=..|RSSI=..

        O pacote carrega texto do usuário e PODE conter '|', então a
        leitura é feita de trás para frente, aceitando só campos
        conhecidos no formato CHAVE=VALOR. Assim um '|' no meio da
        mensagem não engana o separador.
        """

        conhecidos = ("SF", "BW", "CR", "RSSI", "SNR")

        meta = {}

        while "|" in corpo:

            cabeca, _, cauda = corpo.rpartition("|")

            if "=" not in cauda:

                break

            chave, _, valor = cauda.partition("=")

            chave = chave.strip().upper()

            if chave not in conhecidos:

                break

            meta[chave.lower()] = _numero(valor)

            corpo = cabeca

        return corpo, meta

    # -----------------------------------------------------------------
    def _tratar_pacote(self, corpo):

        pacote, meta = self._separar_metadados(corpo)

        radio = {

            "sf": int(meta.get("sf") or self.radio_config["sf"]),

            "bw": float(meta.get("bw") or self.radio_config["bw"]),

            "cr": int(meta.get("cr") or self.radio_config["cr"])

        }

        rssi = meta.get("rssi", self.ultimo_rssi)

        snr = meta.get("snr", self.ultimo_snr)

        # seção 8: tempo de antena calculado, não cronometrado
        tempo = self.tempo_no_ar(pacote, radio)

        evento = {

            "type": "RX_DONE",

            "packet": pacote,

            "time_ms": tempo,

            "radio": radio,

            "rssi": rssi,

            "snr": snr

        }

        self.transmissao_valida.set()

        publicar_evento(evento)

        # fila auxiliar, para quem preferir consumir daqui
        try:

            rx_queue.put_nowait(evento)

        except queue.Full:

            try:

                rx_queue.get_nowait()

                rx_queue.put_nowait(evento)

            except queue.Empty:

                pass

    # -----------------------------------------------------------------
    @staticmethod
    def tempo_no_ar(pacote, radio):
        """
        Seção 8 - quanto tempo esse pacote ocupa o rádio.

        Calculado pelo economy.py. Cronômetro de PC mediria serial mais
        ar e nunca fecharia a mesma conta nos dois nós, o que tornaria a
        seção 21 impossível de verificar.
        """

        if not GhostEconomy:

            return None

        return GhostEconomy.message_time_ms(

            pacote,

            radio["sf"],

            radio["bw"],

            radio["cr"]

        )

    # -----------------------------------------------------------------
    def esperar_pronto(self, timeout=TIMEOUT_RADIO):

        if self.pronto.wait(timeout):

            return True

        print("[RADIO] sem resposta; tentando acordar com RX_START")

        self.enviar("RX_START")

        return self.pronto.wait(5.0)

    def iniciar_rx(self):

        self.pronto.clear()

        self.enviar("RX_START")

        return self.pronto.wait(3.0)

    # -----------------------------------------------------------------
    def configurar(self, radio):
        """
        Seção 21 - aplica SF/BW/CR antes de transmitir.

        Tenta o comando CONFIG (firmware novo). Se o firmware não
        responder, cai para SET_SF/SET_BW/SET_CR.
        """

        alvo = normalizar_radio(radio)

        if alvo is None:

            return False

        atual = self.radio_config

        if (atual["sf"] == alvo["sf"]
                and abs(atual["bw"] - alvo["bw"]) < 0.01
                and atual["cr"] == alvo["cr"]):

            return True

        if self.suporta_config is not False:

            if self._tentar_config(alvo):

                return True

        return self._tentar_set(alvo)

    def _tentar_config(self, alvo):

        self.config_ok.clear()

        self.enviar("CONFIG SF=%d BW=%s CR=%d" % (

            alvo["sf"], _formatar_bw(alvo["bw"]), alvo["cr"]

        ))

        if self.config_ok.wait(TIMEOUT_CONFIG):

            self.suporta_config = True

            self.radio_config = dict(alvo)

            self.iniciar_rx()

            return True

        if self.suporta_config is None:

            print("[RADIO] firmware sem o comando CONFIG; usando SET_*")

        self.suporta_config = False

        return False

    def _tentar_set(self, alvo):

        ok = True

        if self.radio_config["sf"] != alvo["sf"]:

            ok = self._set("SET_SF %d" % alvo["sf"]) and ok

        if abs(self.radio_config["bw"] - alvo["bw"]) >= 0.01:

            ok = self._set("SET_BW %s" % _formatar_bw(alvo["bw"])) and ok

        if self.radio_config["cr"] != alvo["cr"]:

            if not self._set("SET_CR %d" % alvo["cr"]):

                # o firmware antigo não tem SET_CR: o CR fica diferente
                # do original e a recompensa da seção 21 não sai
                if not self.avisou_cr:

                    print("[RADIO] ATENCAO: firmware sem SET_CR.")

                    print("        O CR nao pode ser casado com o da mensagem,")

                    print("        entao a recompensa da secao 21 nao sai.")

                    print("        Grave o firmware corrigido para resolver.")

                    self.avisou_cr = True

                alvo = dict(alvo)

                alvo["cr"] = self.radio_config["cr"]

                ok = False

        self.radio_config = dict(alvo)

        # o firmware antigo deixa a recepção desligada depois de
        # reconfigurar: sem isto o nó fica surdo
        self.iniciar_rx()

        return ok

    def _set(self, comando):

        self.config_ok.clear()

        self.enviar(comando)

        return self.config_ok.wait(TIMEOUT_CONFIG)

    def restaurar_escuta(self):
        """
        O rádio escuta um SF por vez. Depois de transmitir com os
        parâmetros de uma mensagem, volta para a configuração de escuta
        do nó, senão ele para de ouvir os vizinhos.
        """

        return self.configurar(self.listen_config)

    # -----------------------------------------------------------------
    def canal_livre(self):
        """
        Seção 3.1 - escuta obrigatória.

        Com CAD, pergunta ao rádio se há sinal no ar.
        Sem CAD (firmware antigo), não há como saber: assume livre e
        conta com a interrupção da contagem regressiva (seção 3.2).
        """

        if self.suporta_cad is False:

            return True

        while not self.cad_resposta.empty():

            self.cad_resposta.get_nowait()

        self.enviar("CAD", silencioso=True)

        try:

            resposta = self.cad_resposta.get(timeout=TIMEOUT_CAD)

            self.suporta_cad = True

            return resposta

        except queue.Empty:

            if self.suporta_cad is None:

                print("[RADIO] ATENCAO: firmware sem CAD.")

                print("        Sem escuta antes de transmitir (secao 3.1):")

                print("        o no pode falar por cima de quem ja esta no ar.")

            self.suporta_cad = False

            return True

    # -----------------------------------------------------------------
    def transmitir_payload(self, payload):
        """
        Manda o pacote e espera a confirmação do firmware.
        """

        tamanho = len(payload.encode("utf-8"))

        if tamanho > MAX_PAYLOAD:

            print("[RADIO] pacote de %d bytes excede o limite de %d"
                  % (tamanho, MAX_PAYLOAD))

            return False

        if "\n" in payload or "\r" in payload:

            print("[RADIO] pacote com quebra de linha: quebraria a serial")

            return False

        # limpar ANTES de transmitir: um TX_OK antigo fazia a
        # transmissão seguinte "dar certo" na hora
        self.tx_ok.clear()

        self.tx_erro.clear()

        if not self.enviar("TX " + payload):

            return False

        limite = time.monotonic() + TIMEOUT_TX

        while time.monotonic() < limite:

            if self.tx_ok.wait(0.05):

                return True

            if self.tx_erro.is_set():

                print("[RADIO] o firmware recusou a transmissao")

                return False

            if encerrar.is_set():

                return False

        print("[RADIO] TIMEOUT esperando TX_OK")

        return False

    # -----------------------------------------------------------------
    def get_radio_status(self):

        return dict(self.radio_config)

    def get_event(self, timeout=None):

        return mac_events.get(timeout=timeout)

    def esperar_tx(self, timeout=TIMEOUT_TX):
        """
        Mantido para compatibilidade com quem já chamava.
        """

        return self.tx_ok.wait(timeout)


# ===============================
# GHOSTRELAY MAC
# ===============================


class GhostRelayMAC:


    def __init__(self, radio):

        self.radio = radio

        # A fila econômica do protocolo é externa.
        # O MAC não deve competir com outra fila
        # própria de mensagens.
        self.relay_queue = None

        self.backoff_time = BACKOFF_START

        # duas camadas de cima podem pedir transmissão ao mesmo tempo;
        # sem isto as escritas na serial se intercalam
        self.tx_lock = threading.RLock()

        self.transmissoes = 0

        self.disputas_perdidas = 0

    # ===============================
    # CONEXÃO COM RELAY QUEUE
    # ===============================

    def attach_relay_queue(self, relay_queue):

        """
        Liga o MAC à fila oficial.

        Fluxo:

        relay_queue -> MAC -> ESP32
        """

        self.relay_queue = relay_queue

    def enviar_proxima_da_fila(self):

        """
        O MAC solicita a próxima mensagem
        da fila econômica.

        Não utiliza tx_queue paralela.
        """

        if not self.relay_queue:

            return False

        pacote = self.relay_queue.get_next()

        if not pacote:

            return False

        resultado = self.transmitir(pacote)

        if resultado:

            # seção 11: transmitiu, prioridade cai pela metade
            self.relay_queue.mark_transmitted(pacote["hash"])

        return resultado

    # ===============================
    # ESPERA RADIO PRONTO
    # ===============================

    def esperar_radio(self):

        return self.radio.esperar_pronto(TIMEOUT_RADIO)

    # ===============================
    # SUCESSO TX (seção 3.3)
    # ===============================

    def sucesso_tx(self):

        self.backoff_time = min(self.backoff_time * 2, BACKOFF_MAX)

        self.transmissoes += 1

        print("TX SUCESSO")

        print("NOVO BACKOFF:", round(self.backoff_time, 1), "ms")

    # ===============================
    # PERDEU DISPUTA (seção 3.3)
    # ===============================

    def perdeu_disputa(self):

        self.backoff_time = max(self.backoff_time / 2, BACKOFF_MIN)

        self.disputas_perdidas += 1

        print("PERDEU DISPUTA")

        print("NOVO BACKOFF:", round(self.backoff_time, 1), "ms")

    # ===============================
    # ESPERAR O CANAL LIBERAR (seções 3.1 e 3.4)
    # ===============================

    def esperar_canal_livre(self):

        limite = time.monotonic() + TIMEOUT_CANAL

        while time.monotonic() < limite and not encerrar.is_set():

            if self.radio.canal_livre():

                return True

            time.sleep(0.05)

        print("[MAC] canal ocupado tempo demais; seguindo mesmo assim")

        return False

    # ===============================
    # BACKOFF (seção 3.2)
    # ===============================

    def executar_backoff(self):
        """
        Sorteia um tempo dentro da janela e conta.

        Se ouvir uma transmissão válida no meio, para de contar e
        devolve False (perdeu a disputa). Colisão não conta: o firmware
        manda CRC_ERROR e ninguém reage, exatamente como diz a seção 3.3.
        """

        espera = random.uniform(0, self.backoff_time)

        self.radio.transmissao_valida.clear()

        print("BACKOFF ESCOLHIDO:", round(espera, 2), "ms")

        fim = time.monotonic() + (espera / 1000.0)

        while time.monotonic() < fim:

            if encerrar.is_set():

                return False

            if self.radio.transmissao_valida.is_set():

                self.radio.transmissao_valida.clear()

                return False

            time.sleep(TICK)

        return True

    def disputar_canal(self):
        """
        Ciclo completo da seção 3.4.
        """

        while not encerrar.is_set():

            self.esperar_canal_livre()

            if self.executar_backoff():

                return True

            self.perdeu_disputa()

        return False

    # ===============================
    # TRANSMITIR
    # ===============================

    def transmitir(self, msg):

        pacote = normalizar_pacote(msg)

        if not validar_config_radio(pacote):

            print("PACOTE SEM CONFIGURAÇÃO DE RÁDIO")

            publicar_evento({

                "type": "TX_FAILED",

                "hash": pacote.get("hash"),

                "motivo": "sem SF/BW/CR"

            })

            return False

        if not pacote["packet"]:

            return False

        with self.tx_lock:

            if not self.esperar_radio():

                print("RADIO NÃO PRONTO")

                return False

            # seção 21: os mesmos SF/BW/CR com que a mensagem foi ouvida
            if not self.radio.configurar(pacote):

                print("[MAC] nao consegui casar os parametros de radio")

            if not self.disputar_canal():

                return False

            print("TRANSMITINDO:", pacote["packet"][:40],
                  "..." if len(pacote["packet"]) > 40 else "")

            sucesso = self.radio.transmitir_payload(pacote["packet"])

            radio_usado = self.radio.get_radio_status()

            # volta a escutar no SF do nó
            self.radio.restaurar_escuta()

        if not sucesso:

            print("TX FALHOU")

            publicar_evento({

                "type": "TX_FAILED",

                "hash": pacote.get("hash"),

                "motivo": "sem confirmacao do radio"

            })

            enviar_server({"type": "TX_FAILED", "hash": pacote.get("hash")})

            return False

        print("TX FINALIZADO")

        self.sucesso_tx()

        publicar_evento({

            "type": "TX_DONE",

            "hash": pacote.get("hash"),

            "packet": pacote["packet"],

            "time_ms": Radio.tempo_no_ar(pacote["packet"], radio_usado),

            "radio": radio_usado

        })

        enviar_server({"type": "TX_DONE", "hash": pacote.get("hash")})

        return True

    # ===============================
    # LOOP PRINCIPAL
    # ===============================

    def iniciar(self):
        """
        Um único caminho de transmissão.

        Com relay_queue ligada, é ela que manda (é a fila de prioridade
        da seção 11). Sem ela, atende a tx_queue legada. Antes os dois
        rodavam ao mesmo tempo, junto com o main.py chamando transmitir()
        direto: três caminhos disputando a mesma serial.
        """

        if not self.esperar_radio():

            print("FALHA AO INICIAR RADIO")

            return False

        self.radio.iniciar_rx()

        print("GHOSTRELAY MAC ONLINE")

        print("  porta   :", self.radio.port)

        print("  escuta  : SF%d BW%s CR4:%d" % (

            self.radio.listen_config["sf"],

            _formatar_bw(self.radio.listen_config["bw"]),

            self.radio.listen_config["cr"]

        ))

        print("  backoff : %.0f ms" % self.backoff_time)

        while not encerrar.is_set():

            if self.relay_queue:

                if not self.enviar_proxima_da_fila():

                    time.sleep(0.05)

                continue

            try:

                pacote = tx_queue.get(timeout=0.1)

            except queue.Empty:

                continue

            self.transmitir(pacote)

        return True


# ===============================
# SOCKET SERVER.PY
# ===============================


def servidor_socket():

    global server_socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:

        sock.bind((SOCKET_HOST, SOCKET_PORT))

    except OSError as erro:

        print("[MAC] nao consegui abrir a porta", SOCKET_PORT, ":", erro)

        return

    sock.listen(1)

    print("MAC SOCKET ONLINE")

    while not encerrar.is_set():

        try:

            conn, addr = sock.accept()

        except OSError:

            break

        print("SERVER CONECTADO", addr)

        with server_lock:

            server_socket = conn

        # Antes o recv era lido direto: dois comandos no mesmo pacote
        # TCP viravam um só, e comando partido ao meio se perdia.
        buffer = b""

        try:

            while not encerrar.is_set():

                dados = conn.recv(4096)

                if not dados:

                    break

                buffer += dados

                while b"\n" in buffer:

                    linha, buffer = buffer.split(b"\n", 1)

                    tratar_comando(linha.decode("utf-8", "ignore").strip())

        except OSError:

            pass

        finally:

            print("SERVER DESCONECTADO")

            with server_lock:

                if server_socket is conn:

                    server_socket = None

            try:

                conn.close()

            except OSError:

                pass


def tratar_comando(msg):
    """
    Aceita o formato antigo "TX <texto>" e o JSON TX_REQUEST.
    """

    if not msg:

        return

    if msg.startswith("TX "):

        tx_queue.put(msg[3:])

        print("TX QUEUE:", tx_queue.qsize())

        return

    try:

        pedido = json.loads(msg)

    except ValueError:

        return

    if not isinstance(pedido, dict):

        return

    if pedido.get("type") == "TX_REQUEST":

        tx_queue.put({

            "packet": pedido.get("packet", pedido.get("data", "")),

            "hash": pedido.get("hash"),

            "sf": pedido.get("sf"),

            "bw": pedido.get("bw"),

            "cr": pedido.get("cr")

        })

        print("TX QUEUE:", tx_queue.qsize())

    else:

        mac_commands.put(pedido)


# ===============================
# START
# ===============================


if __name__ == "__main__":

    print(
"""
==========================
 GHOSTRELAY MAC SERVER
==========================
"""
    )

    radio = Radio()

    threading.Thread(

        target=servidor_socket,

        daemon=True,

        name="socket"

    ).start()

    mac = GhostRelayMAC(radio)

    try:

        mac.iniciar()

    except KeyboardInterrupt:

        print("\nencerrando...")

        encerrar.set()
