#!/usr/bin/env python3

"""
GhostRelay - Teste de enlace de rádio

Fala DIRETO com o firmware, sem protocolo nenhum: sem carteira, sem
assinatura, sem hash, sem cache, sem fila. Serve para responder uma
pergunta só:

    os dois rádios se ouvem?

Se este teste funciona e o main.py não, o problema é de protocolo.
Se nem este funciona, o problema é de rádio, antena, configuração ou
alimentação - e aí não adianta procurar no Python.

USO
---
Em duas máquinas (ou dois terminais, com dois ESP32):

    máquina A:   python3 teste_radio.py --rx
    máquina B:   python3 teste_radio.py --tx "ola"

Para testar nos dois sentidos ao mesmo tempo:

    máquina A:   python3 teste_radio.py --tx "de A" --intervalo 10
    máquina B:   python3 teste_radio.py --tx "de B" --intervalo 10

(com intervalo grande os dois passam a maior parte do tempo escutando,
que é exatamente o que falta quando o nó normal está rodando)

Trocar a configuração dos dois lados:

    python3 teste_radio.py --rx --sf 9 --bw 250 --cr 7

IMPORTANTE: feche o main.py antes. Dois processos não abrem a mesma
porta serial.
"""

import argparse
import glob
import os
import sys
import threading
import time

try:

    import serial

except ImportError:

    print("ERRO: falta a biblioteca pyserial.  pip install pyserial")

    raise SystemExit(1)


BAUD = 115200


# a thread que lê a serial e a que transmite escrevem na mesma tela
_tela = threading.Lock()


def linha(texto):

    with _tela:

        print(texto)


def detectar_porta():

    for padrao in ("/dev/ttyACM*", "/dev/ttyUSB*",
                   "/dev/cu.usbserial*", "/dev/cu.wchusbserial*",
                   "/dev/cu.SLAB*"):

        achados = sorted(glob.glob(padrao))

        if achados:

            return achados[0]

    return "/dev/ttyACM0"


def agora():

    return time.strftime("%H:%M:%S")


# =====================================================
# LIGAÇÃO COM O FIRMWARE
# =====================================================

class Radio:


    def __init__(self, porta):

        self.porta = porta

        print("[*] abrindo", porta)

        try:

            self.ser = serial.Serial(porta, BAUD, timeout=0.2)

        except serial.SerialException as erro:

            print("[X] nao consegui abrir a porta:", erro)

            print("    o main.py ou o monitor serial da IDE estao abertos?")

            raise SystemExit(1)

        self.rodando = True

        self.recebidos = 0

        self.transmitidos = 0

        self.crc_errados = 0

        self.config = {}

        self.caps = None

        self.tx_ok = threading.Event()

        self.pronto = threading.Event()

        threading.Thread(target=self._ler, daemon=True).start()

        print("[*] esperando o boot do ESP32 (reset pelo DTR)...")

        time.sleep(3)


    # -------------------------------------------------
    def enviar(self, cmd):

        self.ser.write((cmd + "\n").encode("ascii", "ignore"))

        self.ser.flush()


    # -------------------------------------------------
    def _ler(self):

        while self.rodando:

            try:

                texto = self.ser.readline().decode("ascii", "ignore").strip()

            except Exception:

                time.sleep(0.05)

                continue

            if not texto:

                continue

            self._tratar(texto)


    def _tratar(self, texto):

        # o pacote em si
        if texto.startswith("MSG:"):

            self._mostrar_pacote(texto[4:])

            return

        if texto.startswith("EVENT:CMD_RECEIVED"):

            return

        if not texto.startswith("EVENT:"):

            # STATUS devolve FREQ:, BW:, SF:, CR:, POWER:, RX:
            if ":" in texto:

                chave, _, valor = texto.partition(":")

                self.config[chave] = valor

            return

        evento = texto[6:]

        if evento in ("READY", "RX_STARTED", "RADIO_OK"):

            self.pronto.set()

        elif evento == "TX_OK":

            self.tx_ok.set()

        elif evento == "BOOT":

            linha("%s  [!] o ESP32 reiniciou\n"
                  "      se isso acontecer durante a transmissao, e\n"
                  "      alimentacao: 22 dBm puxa muita corrente" % agora())

        elif evento.startswith("CAPS:"):

            self.caps = evento[5:]

        elif evento in ("CRC_ERROR", "RX_CRC_ERROR"):

            self.crc_errados += 1

            linha("%s  [!] pacote corrompido (CRC) - alguem esta no ar,"
                  " mas chegou quebrado" % agora())

        elif evento.startswith("RX_DISCARDED"):

            linha("%s  [!] pacote descartado pelo firmware: %s"
                  % (agora(), evento))

        elif evento.startswith(("INIT_ERROR", "RX_ERROR",
                                "TX_ERROR", "CONFIG_ERROR")):

            linha("%s  [X] %s" % (agora(), texto))

        elif evento.startswith("CAD_"):

            linha("%s  [*] %s" % (agora(), texto))


    def _mostrar_pacote(self, corpo):

        # MSG:<pacote>|SF=..|BW=..|CR=..|RSSI=..|SNR=..
        conhecidos = ("SF", "BW", "CR", "RSSI", "SNR")

        meta = {}

        while "|" in corpo:

            cabeca, _, cauda = corpo.rpartition("|")

            if "=" not in cauda:

                break

            chave, _, valor = cauda.partition("=")

            if chave.strip().upper() not in conhecidos:

                break

            meta[chave.strip().upper()] = valor

            corpo = cabeca

        self.recebidos += 1

        amostra = corpo if len(corpo) <= 40 else corpo[:40] + "..."

        linha("%s  RX #%-4d %-45s %s" % (

            agora(),

            self.recebidos,

            '"' + amostra + '"',

            "| SF%s BW%s CR4:%s | RSSI %s dBm | SNR %s dB | %d bytes" % (

                meta.get("SF", "?"), meta.get("BW", "?"), meta.get("CR", "?"),

                meta.get("RSSI", "?"), meta.get("SNR", "?"), len(corpo)

            )

        ))


    # -------------------------------------------------
    def configurar(self, sf, bw, cr, freq):

        partes = []

        if sf:   partes.append("SF=%d" % sf)

        if bw:   partes.append("BW=%s" % bw)

        if cr:   partes.append("CR=%d" % cr)

        if freq: partes.append("FREQ=%s" % freq)

        if not partes:

            return

        cmd = "CONFIG " + " ".join(partes)

        print("[*]", cmd)

        self.enviar(cmd)

        time.sleep(1.0)


    def status(self):

        self.enviar("STATUS")

        time.sleep(1.0)

        print("[*] configuracao do radio:")

        for campo in ("FREQ", "BW", "SF", "CR", "POWER", "RX"):

            if campo in self.config:

                print("      %-6s %s" % (campo, self.config[campo]))

        if self.caps:

            print("      firmware: %s" % self.caps)

        else:

            print("      firmware: nao anunciou capacidades (versao antiga)")


    def fechar(self):

        self.rodando = False

        time.sleep(0.3)

        try:

            self.ser.close()

        except Exception:

            pass


# =====================================================
# MODOS
# =====================================================

def modo_rx(radio):

    print("""
==================================================
 MODO ESCUTA
==================================================
 Tudo que chegar aparece aqui. Ctrl+C para sair.

 Nada aparecendo? Confira, nesta ordem:
   1. os dois radios estao no MESMO SF, BW, CR e frequencia
   2. antena conectada nos dois
   3. afaste os modulos alguns metros - a menos de 1 m
      eles podem saturar um ao outro
==================================================
""")

    radio.enviar("RX_START")

    try:

        while True:

            time.sleep(1)

    except KeyboardInterrupt:

        pass


def modo_tx(radio, texto, intervalo, quantidade):

    print("""
==================================================
 MODO TRANSMISSAO
==================================================
 Intervalo: %.1f s   |   Ctrl+C para sair
==================================================
""" % intervalo)

    radio.enviar("RX_START")

    time.sleep(0.5)

    enviados = 0

    confirmados = 0

    try:

        while quantidade == 0 or enviados < quantidade:

            enviados += 1

            payload = "%s %d" % (texto, enviados)

            radio.tx_ok.clear()

            inicio = time.time()

            radio.enviar("TX " + payload)

            if radio.tx_ok.wait(30):

                confirmados += 1

                radio.transmitidos += 1

                linha("%s  TX #%-4d %-45s | %.2f s no ar | OK"
                      % (agora(), enviados, '"' + payload + '"',
                         time.time() - inicio))

            else:

                linha("%s  TX #%-4d %-45s | SEM CONFIRMACAO"
                      % (agora(), enviados, '"' + payload + '"'))

            # Fica escutando no intervalo. E de proposito: e exatamente
            # isso que o no normal nao faz quando tem algo na fila.
            time.sleep(intervalo)

    except KeyboardInterrupt:

        pass

    print("\n  enviados: %d | confirmados pelo radio: %d" % (enviados, confirmados))


def modo_ping(radio):

    print("\n[*] PING")

    radio.enviar("PING")

    time.sleep(1)

    print("[*] CAD (escuta do canal)")

    radio.enviar("CAD")

    time.sleep(2)


# =====================================================
def main():

    ap = argparse.ArgumentParser(

        description="Testa o enlace de radio, sem o protocolo GhostRelay"

    )

    ap.add_argument("--porta")

    ap.add_argument("--rx", action="store_true", help="so escuta")

    ap.add_argument("--tx", metavar="TEXTO", help="transmite este texto")

    ap.add_argument("--ping", action="store_true", help="so testa a placa")

    ap.add_argument("--intervalo", type=float, default=5.0,
                    help="segundos entre transmissoes (padrao 5)")

    ap.add_argument("--quantidade", type=int, default=0,
                    help="quantas transmitir (0 = sem parar)")

    ap.add_argument("--sf", type=int)

    ap.add_argument("--bw")

    ap.add_argument("--cr", type=int)

    ap.add_argument("--freq")

    args = ap.parse_args()

    if not (args.rx or args.tx or args.ping):

        ap.print_help()

        print("""
Exemplo mais comum, em duas maquinas:

    maquina A:   python3 teste_radio.py --rx
    maquina B:   python3 teste_radio.py --tx "ola"
""")

        return 1

    porta = args.porta or os.environ.get("GHOST_PORTA") or detectar_porta()

    radio = Radio(porta)

    if not radio.pronto.wait(6):

        print("[X] o radio nao respondeu.")

        print("    sem EVENT:READY, o problema esta antes do ar:")
        print("    SPI, pinos NSS/BUSY/RESET, ou a configuracao de TCXO")

        radio.fechar()

        return 1

    radio.configurar(args.sf, args.bw, args.cr, args.freq)

    radio.status()

    try:

        if args.ping:

            modo_ping(radio)

        elif args.rx:

            modo_rx(radio)

        else:

            modo_tx(radio, args.tx, args.intervalo, args.quantidade)

    finally:

        print("""
==================================================
 RESUMO
==================================================
 pacotes recebidos     : %d
 pacotes transmitidos  : %d
 pacotes com CRC errado: %d
==================================================""" % (

            radio.recebidos, radio.transmitidos, radio.crc_errados

        ))

        if radio.crc_errados and not radio.recebidos:

            print("""
 So CRC errado: o enlace EXISTE (o radio ouviu algo), mas chega
 corrompido. Sinal fraco demais, ou os dois transmitindo juntos.""")

        elif not radio.recebidos and not radio.crc_errados:

            print("""
 Nada chegou. Confira, nesta ordem:
   1. os dois lados no MESMO SF/BW/CR/frequencia (--sf --bw --cr)
   2. antena conectada
   3. distancia: nem longe demais, nem a menos de 1 metro
   4. o outro lado esta mesmo transmitindo? (--tx)""")

        radio.fechar()

    return 0


if __name__ == "__main__":

    sys.exit(main())
