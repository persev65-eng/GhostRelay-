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
"""


import time
from collections import deque



class RelayQueue:


    def __init__(
        self,
        max_size=1000
    ):

        self.max_size = max_size

        self.queue = deque()


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
        da mensagem original.
        """


        # FIFO manual:
        # remove a mais antiga quando lotar

        if len(self.queue) >= self.max_size:

            self.queue.popleft()



        item = {

            "packet": packet,

            "hash": msg_hash,

            "type": msg_type,

            "priority": float(priority),

            "sf": sf,

            "bw": bw,

            "cr": cr,

            "created": time.time(),

            "transmissions": 0

        }



        self.queue.append(
            item
        )


        return item



    # =================================================
    # PEGAR PRÓXIMA MENSAGEM
    # =================================================


    def get_next(self):

        """
        Retorna a mensagem
        com maior prioridade.
        """


        if not self.queue:

            return None



        return max(

            self.queue,

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



        for item in self.queue:


            if item["hash"] == msg_hash:


                item["priority"] /= 2


                item["transmissions"] += 1


                return item



        return None




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


        for item in self.queue:


            if item["hash"] == msg_hash:

                return {

                    "sf": item["sf"],

                    "bw": item["bw"],

                    "cr": item["cr"]

                }


        return None



    # =================================================
    # REMOVER
    # =================================================


    def remove(
        self,
        msg_hash
    ):


        for item in list(self.queue):


            if item["hash"] == msg_hash:


                self.queue.remove(
                    item
                )


                return True



        return False



    # =================================================
    # CONSULTAR
    # =================================================


    def size(self):

        return len(
            self.queue
        )



    def empty(self):

        return len(
            self.queue
        ) == 0



    def get_all(self):

        return list(
            self.queue
        )



    # =================================================
    # LIMPAR
    # =================================================


    def clear(self):

        self.queue.clear()





# =====================================================
# TESTE
# =====================================================


if __name__ == "__main__":


    relay = RelayQueue(
        max_size=3
    )


    relay.add(
        "MSG_A",
        "HASH_A",
        100,
        sf=12,
        bw=250,
        cr=7
    )


    relay.add(
        "MSG_B",
        "HASH_B",
        500,
        sf=12,
        bw=250,
        cr=7
    )


    print(
        relay.get_next()
    )


    relay.mark_transmitted(
        "HASH_B"
    )


    print(
        relay.get_all()
    )
