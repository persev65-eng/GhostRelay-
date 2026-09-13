#!/usr/bin/env python3

"""
GhostRelay - Relay Queue

Fila de retransmissão.

Responsabilidade:

- Guardar mensagens aguardando TX
- Ordenar por prioridade
- Reduzir prioridade após transmissão
- Remover mensagens antigas quando lotar
- Preservar parâmetros originais de rádio

Não controla:
- assinatura
- hash
- pontos
- vizinhos
- rádio


COMO A FILA FUNCIONA (seções 11 e 23)
-------------------------------------
Sai sempre a mensagem de MAIOR prioridade. Entre prioridades iguais,
quem chegou primeiro fala primeiro.

Depois de transmitida, a prioridade cai pela metade:

    na fila            100
    1a transmissão      50
    2a transmissão      25
    3a transmissão    12,5

E a mensagem CONTINUA NA FILA. Ela não sai por ter sido transmitida um
número de vezes: retransmitir a mesma mensagem é parte do protocolo, é
o que aumenta a chance dela atravessar a rede. Ela sai quando a fila
lota e ela é a mais antiga (FIFO, seção 23).

Por isso get_next() NÃO remove o item. Quem mexer aqui depois, atenção:
isso não é um descuido, é a regra. O que faz a mensagem parar de ser
escolhida é a prioridade dela despencar perante as outras.


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) A MESMA MENSAGEM PODIA OCUPAR VÁRIAS POSIÇÕES DA FILA.

   add() não conferia se o hash já estava lá. Pior: mark_transmitted()
   só encontrava a PRIMEIRA ocorrência, então a segunda cópia nunca
   tinha a prioridade reduzida. Ela ficaria no topo para sempre,
   transmitida sem parar, sem nunca perder prioridade.

   Agora uma mensagem ocupa uma posição só. Registrar de novo mantém a
   maior prioridade entre as duas e atualiza o pacote.

2) TODA OPERAÇÃO ERA UMA VARREDURA LINEAR.

   get_next(), mark_transmitted(), remove() e get_radio_config()
   percorriam até 1000 itens. mark_transmitted roda a cada
   transmissão, get_next roda em laço no MAC.

3) SEM PROTEÇÃO ENTRE THREADS.

   O laço do MAC tira da fila enquanto a thread que processa recepção
   coloca. Sem lock, dá para perder item ou ler estado pela metade.

4) SF/BW/CR ENTRAVAM SEM VALIDAÇÃO.

   Item sem configuração de rádio é recusado pelo MAC na hora de
   transmitir (seção 21) e ficaria preso na fila, sendo escolhido de
   novo e de novo. Agora a fila normaliza na entrada e avisa.

5) attach_mac() + transmit_next() CRIAVAM UM SEGUNDO CAMINHO DE
   TRANSMISSÃO, concorrendo com o laço do próprio MAC. Continuam aqui
   para compatibilidade, mas com aviso: use um OU outro.


SOBRE PERSISTÊNCIA
------------------
Esta fila não é salva em disco de propósito, diferente do cache, dos
vizinhos e da lista corrida.

Ela é trabalho em andamento, não memória econômica. Um nó que ficou uma
hora desligado e voltasse retransmitindo tudo que estava pendente
jogaria no ar mensagens que a rede já esqueceu - gastando antena de
todo mundo para propagar eco velho.
"""


import threading
import time

from collections import OrderedDict

try:

    from economy import GhostEconomy

except Exception:

    GhostEconomy = None


class RelayQueue:


    def __init__(
        self,
        max_size=1000
    ):

        self.max_size = max(1, int(max_size))

        # hash -> item. OrderedDict dá busca direta E ordem de chegada,
        # que é o que a política FIFO da seção 23 precisa.
        self.queue = OrderedDict()

        self.lock = threading.RLock()

        self.descartadas = 0

        self.transmissoes = 0


        # Referência opcional ao MAC.
        # O relay_queue continua independente,
        # mas pode entregar pacotes diretamente
        # ao transmissor quando conectado.

        self.mac = None




    # =================================================
    # CONEXÃO COM MAC
    # =================================================


    def attach_mac(
        self,
        mac
    ):

        """
        Conecta a fila ao módulo MAC.

        Fluxo:

        relay_queue.get_next()

                |

                v

              mac.transmitir()

                |

                v

        relay_queue.mark_transmitted()


        ATENÇÃO: o MAC também sabe puxar da fila sozinho
        (mac.attach_relay_queue). Use um caminho OU o outro. Os dois
        ligados ao mesmo tempo fazem duas threads disputarem a serial.
        """


        self.mac = mac



    def transmit_next(
        self
    ):

        """
        Envia a próxima mensagem
        de maior prioridade para o MAC.

        A fila continua sendo a dona
        da decisão de prioridade.
        """


        if not self.mac:

            return None



        item = self.get_next()



        if not item:

            return None



        try:


            resultado = self.mac.transmitir(
                item
            )


            if resultado:


                self.mark_transmitted(
                    item["hash"]
                )



            return resultado


        except Exception:


            return False



    # =================================================
    # ADICIONAR MENSAGEM
    # =================================================


    def add(
        self,
        packet,
        msg_hash,
        priority,
        msg_type="MESSAGE",
        sf=None,
        bw=None,
        cr=None
    ):

        """
        Adiciona mensagem na fila.

        Guarda:

        - pacote pronto para transmissão
        - hash
        - tipo
        - prioridade
        - configuração de rádio original

        Tipos:

        MESSAGE
        INVITE

        SF/BW/CR são preservados para que
        a retransmissão use a mesma configuração
        da mensagem original (seção 21).

        Uma mensagem ocupa UMA posição. Se o hash já estiver na fila,
        fica valendo a maior prioridade entre as duas e o pacote é
        atualizado - o conteúdo é o mesmo, só a assinatura é mais nova.
        """

        if not msg_hash or not packet:

            return None

        radio = self._normalizar_radio(sf, bw, cr)

        if radio is None:

            # sem SF/BW/CR o MAC recusa na hora de transmitir e o item
            # ficaria preso aqui, sendo escolhido de novo e de novo
            print("[FILA] item sem SF/BW/CR completo, recusado:",
                  str(msg_hash)[:12])

            return None

        with self.lock:

            existente = self.queue.get(msg_hash)

            if existente:

                existente["priority"] = max(

                    existente["priority"],

                    float(priority)

                )

                existente["packet"] = packet

                return existente


            item = {

                "packet": packet,

                "hash": msg_hash,

                "type": msg_type,

                "priority": float(priority),

                "sf": radio["sf"],

                "bw": radio["bw"],

                "cr": radio["cr"],

                "created": time.time(),

                "transmissions": 0

            }



            self.queue[msg_hash] = item

            # FIFO: quando lota, sai a mais antiga (seção 23)
            self._aparar()


            return item


    def _aparar(self):
        """
        Chamado sempre com o lock adquirido.
        """

        while len(self.queue) > self.max_size:

            self.queue.popitem(last=False)

            self.descartadas += 1


    @staticmethod
    def _normalizar_radio(sf, bw, cr):
        """
        Aceita 250/250.0/"250" e 7/"4/7"/47, como o resto do projeto.
        """

        if sf is None or bw is None or cr is None:

            return None

        if GhostEconomy:

            return GhostEconomy.normalize_radio(

                {"sf": sf, "bw": bw, "cr": cr}

            )

        try:

            return {

                "sf": int(sf),

                "bw": float(bw),

                "cr": int(cr)

            }

        except (TypeError, ValueError):

            return None



    # =================================================
    # PEGAR PRÓXIMA MENSAGEM
    # =================================================


    def get_next(self):

        """
        Retorna a mensagem
        com maior prioridade.

        NÃO remove da fila: a mensagem só sai por FIFO (seções 11 e 23).
        Entre prioridades iguais vence a mais antiga.
        """

        with self.lock:

            if not self.queue:

                return None



            return max(

                self.queue.values(),

                key=lambda x:
                x["priority"]

            )



    # =================================================
    # TRANSMISSÃO REALIZADA
    # =================================================


    def mark_transmitted(
        self,
        msg_hash
    ):

        """
        Depois que o MAC transmite:

        prioridade / 2
        """

        with self.lock:

            item = self.queue.get(msg_hash)

            if item is None:

                return None

            item["priority"] /= 2

            item["transmissions"] += 1

            self.transmissoes += 1

            return item




    # =================================================
    # FINALIZAÇÃO DE TRANSMISSÃO
    # =================================================


    def transmission_complete(
        self,
        msg_hash
    ):

        """
        Chamado pelo MAC após
        confirmação real de TX.

        Mantém compatibilidade com
        arquiteturas onde o MAC é
        assíncrono.
        """


        return self.mark_transmitted(
            msg_hash
        )



    # =================================================
    # CONFIGURAÇÃO DE RÁDIO
    # =================================================


    def get_radio_config(
        self,
        msg_hash
    ):

        """
        Retorna SF/BW/CR
        da mensagem.
        """

        with self.lock:

            item = self.queue.get(msg_hash)

            if item is None:

                return None

            return {

                "sf": item["sf"],

                "bw": item["bw"],

                "cr": item["cr"]

            }



    # =================================================
    # REMOVER
    # =================================================


    def remove(
        self,
        msg_hash
    ):

        with self.lock:

            if msg_hash in self.queue:

                del self.queue[msg_hash]

                return True

            return False



    # =================================================
    # CONSULTAR
    # =================================================


    def size(self):

        with self.lock:

            return len(
                self.queue
            )



    def empty(self):

        with self.lock:

            return len(
                self.queue
            ) == 0



    def get_all(self):
        """
        Da mais antiga para a mais nova (ordem de chegada).
        """

        with self.lock:

            return list(
                self.queue.values()
            )


    def get(self, msg_hash):

        with self.lock:

            return self.queue.get(msg_hash)


    def ordenada(self):
        """
        Da maior prioridade para a menor: a ordem em que as mensagens
        vão ao ar se nada mais entrar na fila.
        """

        with self.lock:

            return sorted(

                self.queue.values(),

                key=lambda x: -x["priority"]

            )


    def resumo(self):

        with self.lock:

            return {

                "itens": len(self.queue),

                "limite": self.max_size,

                "mensagens": sum(
                    1 for i in self.queue.values() if i["type"] == "MESSAGE"
                ),

                "convites": sum(
                    1 for i in self.queue.values() if i["type"] == "INVITE"
                ),

                "transmissoes": self.transmissoes,

                "descartadas_fifo": self.descartadas

            }



    # =================================================
    # LIMPAR
    # =================================================


    def clear(self):

        with self.lock:

            self.queue.clear()





# =====================================================
# TESTE
# =====================================================


if __name__ == "__main__":

    RADIO = {"sf": 12, "bw": 250, "cr": 7}

    relay = RelayQueue(max_size=3)

    print("=" * 58)
    print(" SEÇÃO 11 - MAIOR PRIORIDADE PRIMEIRO")
    print("=" * 58)

    relay.add("MSG_A", "HASH_A", 100, **RADIO)

    relay.add("MSG_B", "HASH_B", 500, **RADIO)

    print("  na fila: A com 100, B com 500")

    print("  proxima a transmitir:", relay.get_next()["hash"])

    print("\n" + "=" * 58)
    print(" PRIORIDADE CAI PELA METADE, MENSAGEM FICA")
    print("=" * 58)

    for i in range(4):

        proxima = relay.get_next()

        relay.mark_transmitted(proxima["hash"])

        print("  transmitiu %s -> prioridade agora %7.2f | continua na fila: %s"
              % (proxima["hash"], proxima["priority"],
                 relay.get(proxima["hash"]) is not None))

    print("\n  ordem de saida agora:")

    for item in relay.ordenada():

        print("    %-8s prioridade %7.2f | %d transmissoes"
              % (item["hash"], item["priority"], item["transmissions"]))

    print("\n" + "=" * 58)
    print(" UMA MENSAGEM, UMA POSIÇÃO")
    print("=" * 58)

    relay.add("MSG_A_DE_NOVO", "HASH_A", 900, **RADIO)

    print("  registrar HASH_A de novo com prioridade 900")
    print("  itens na fila:", relay.size())
    print("  prioridade de HASH_A agora:", relay.get("HASH_A")["priority"])

    print("\n" + "=" * 58)
    print(" SEÇÃO 23 - FIFO")
    print("=" * 58)

    for i in range(3):

        relay.add("MSG_%d" % i, "HASH_%d" % i, 10, **RADIO)

    print("  limite %d | itens %d" % (relay.max_size, relay.size()))
    print("  HASH_A sobreviveu?", relay.get("HASH_A") is not None)
    print("  resumo:", relay.resumo())
