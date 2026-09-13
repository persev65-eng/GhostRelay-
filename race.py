#!/usr/bin/env python3

"""
GhostRelay - Race List

Lista econômica das mensagens em circulação.

Responsabilidade:

- Registrar mensagens criadas pelo nó
- Guardar valor econômico
- Detectar retorno da mensagem
- Recompensar retransmissores
- Reduzir valor por salto


Não controla:
- assinatura
- rádio
- fila
- vizinhos


COMO A RECOMPENSA FUNCIONA (seção 10)
-------------------------------------
Um nó pode retransmitir a mesma mensagem quantas vezes quiser: é isso
que dá à mensagem mais chances de atravessar a rede.

Cada retorno ocupa uma POSIÇÃO na lista de recompensa daquela mensagem,
e cada posição vale metade da anterior -- não importa quem retornou:

    mensagem vale 100

    1o retorno -> B     100 pontos
    2o retorno -> C      50 pontos
    3o retorno -> B      25 pontos
    4o retorno -> ...  12,5 pontos

A mesma carteira pode ocupar várias posições (adendo da seção 10).
O freio é econômico, não uma regra: repetir custa o mesmo tempo de
antena e rende metade.

A entrada continua pagando até sair da lista, e ela só sai por FIFO,
quando a lista lota (seção 23). Não existe valor mínimo nem prazo.


O QUE ENTRA AQUI
----------------
- Mensagem própria, no momento em que é criada (seções 5 e 7).
- Mensagem que eu retransmiti (seção 20, item 6). É isso que me permite
  recompensar - e promover, pela seção 19 - quem continuar carregando
  tráfego que não nasceu comigo.

Convite NUNCA entra: ele não gera recompensa (seção 12).


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) A SEÇÃO 21 NÃO TINHA COMO SER APLICADA.

   A entrada guardava hash e pontos, mas não com que SF/BW/CR a
   mensagem saiu. Sem isso não há como cumprir "o autor só dará pontos
   se a mensagem que voltou tiver exatamente o mesmo SF, BW e CR".
   reward_relay() pagava qualquer retorno, inclusive de quem
   retransmitisse num SF mais barato para gastar menos antena e
   receber o mesmo.

2) PAGAVA SEM SABER PARA QUEM.

   helper_key era opcional: reward_relay("hash") consumia uma posição
   da lista e devolvia os pontos sem registrar ajudante nenhum.

3) find() ERA UMA VARREDURA LINEAR.

   Percorria até 1000 entradas, a cada pacote recebido, duas vezes
   (find e depois reward_relay chamando find de novo). Agora é busca
   direta por hash, e a ordem FIFO continua preservada.

4) add_message() ACEITAVA O MESMO HASH DUAS VEZES.

   Criava duas entradas para a mesma mensagem; find() só achava a
   primeira e a segunda ficava ocupando posição à toa.

5) helpers E rewards CRESCIAM SEM LIMITE.

   Como não há teto de retornos, o histórico de uma entrada crescia
   indefinidamente.

6) SEM PERSISTÊNCIA E SEM LOCK.

   Reiniciar o nó apagava as mensagens em circulação: quem ainda
   estivesse carregando uma mensagem sua não receberia nada ao
   devolvê-la. E a lista é tocada pela thread do rádio e pelo laço
   principal ao mesmo tempo.
"""


import threading
import time
from collections import OrderedDict


try:

    from economy import GhostEconomy

except Exception:

    GhostEconomy = None


# Quantas posições de histórico guardar por entrada
MAX_HISTORICO = 64


class RaceList:


    def __init__(
        self,
        max_size=1000,
        storage=None
    ):

        self.max_size = max(1, int(max_size))

        self.storage = storage

        # OrderedDict: busca direta por hash E ordem de chegada,
        # que é o que a política FIFO da seção 23 precisa
        self.entries = OrderedDict()

        self.lock = threading.RLock()

        self.total_pago = 0.0

        self.descartadas = 0

        if self.storage:

            self.load()



    # =================================================
    # ADICIONAR MENSAGEM NA CORRIDA
    # =================================================


    def add_message(
        self,
        msg_hash,
        points,
        radio=None,
        own=True
    ):

        """
        Seções 7 e 8 - a entrada é o hash mais o valor em pontos, e o
        valor é o tempo de antena da mensagem.

        radio guarda com que SF/BW/CR ela saiu. É essa cópia que a
        seção 21 compara quando a mensagem volta.

        Chamar duas vezes com o mesmo hash não cria outra entrada:
        a mensagem é uma só, por mais vezes que seja transmitida.
        """

        if not msg_hash:

            return None

        with self.lock:

            if msg_hash in self.entries:

                return self.entries[msg_hash]

            entry = {


                "hash": msg_hash,


                "initial_points": float(points),


                "current_points": float(points),


                "radio": dict(radio) if radio else None,


                "own": bool(own),


                "created": time.time(),


                "hits": 0,


                "total_paid": 0.0,


                # Histórico de nós que ajudaram.
                # Cada posição representa uma retransmissão
                # válida detectada pela corrida.

                "helpers": [],


                # Guarda pagamentos já calculados.

                "rewards": []


            }


            self.entries[msg_hash] = entry

            self._aparar()

            return entry


    def _aparar(self):
        """
        Seção 23 - quando a lista lota, sai a mais antiga.
        Chamado sempre com o lock adquirido.
        """

        while len(self.entries) > self.max_size:

            self.entries.popitem(last=False)

            self.descartadas += 1



    # =================================================
    # PROCURAR MENSAGEM
    # =================================================


    def find(
        self,
        msg_hash
    ):

        """
        Procura mensagem na corrida.
        """

        with self.lock:

            return self.entries.get(msg_hash)


    def exists(self, msg_hash):

        with self.lock:

            return msg_hash in self.entries



    # =================================================
    # SEÇÃO 21 - FIDELIDADE DE RÁDIO
    # =================================================


    def radio_confere(self, msg_hash, radio):
        """
        O retorno veio com o mesmo SF/BW/CR da transmissão original?

        Entrada sem rádio registrado passa: é mensagem antiga, gravada
        antes desta informação existir, e recusar seria pior.
        """

        entry = self.find(msg_hash)

        if entry is None:

            return False

        original = entry.get("radio")

        if not original:

            return True

        if not radio:

            return False

        if GhostEconomy:

            return GhostEconomy.reward_allowed(original, radio)

        return (

            original.get("sf") == radio.get("sf")

            and original.get("bw") == radio.get("bw")

            and original.get("cr") == radio.get("cr")

        )



    # =================================================
    # MENSAGEM FOI RETRANSMITIDA
    # =================================================


    def process_return(
        self,
        msg_hash,
        helper_key,
        radio=None
    ):

        """
        Um nó devolveu uma mensagem que está nesta lista.

        Devolve:

            {
              "ok": pagou ou não,
              "pontos": quanto foi pago,
              "motivo": por que não pagou,
              "posicao": qual posição da lista ele ocupou,
              "proximo": quanto vale a próxima posição
            }

        Retorno recusado NÃO consome posição: quem transmitiu com outro
        SF não ocupa lugar na fila de recompensa nem empurra o valor
        para baixo para os próximos.
        """

        with self.lock:

            entry = self.entries.get(msg_hash)

            if entry is None:

                return {

                    "ok": False,

                    "pontos": 0.0,

                    "motivo": "fora da lista corrida",

                    "posicao": 0,

                    "proximo": 0.0

                }

            if not helper_key:

                return {

                    "ok": False,

                    "pontos": 0.0,

                    "motivo": "sem carteira do retransmissor",

                    "posicao": entry["hits"],

                    "proximo": entry["current_points"]

                }

            # Seção 21 - sem os mesmos parâmetros, sem recompensa
            if not self.radio_confere(msg_hash, radio):

                return {

                    "ok": False,

                    "pontos": 0.0,

                    "motivo": "SF/BW/CR diferentes do original",

                    "posicao": entry["hits"],

                    "proximo": entry["current_points"]

                }

            reward = entry["current_points"]

            entry["hits"] += 1

            entry["total_paid"] += reward

            self.total_pago += reward

            entry["helpers"].append(helper_key)

            entry["rewards"].append({

                "node": helper_key,

                "points": reward,

                "time": time.time()

            })

            # o histórico é diagnóstico, não protocolo: não pode crescer
            # sem fim só porque a mensagem continua circulando
            if len(entry["helpers"]) > MAX_HISTORICO:

                del entry["helpers"][:-MAX_HISTORICO]

                del entry["rewards"][:-MAX_HISTORICO]

            # Seção 10 - a próxima posição vale metade
            entry["current_points"] /= 2

            return {

                "ok": True,

                "pontos": reward,

                "motivo": "ok",

                "posicao": entry["hits"],

                "proximo": entry["current_points"]

            }


    def reward_relay(
        self,
        msg_hash,
        helper_key=None,
        radio=None
    ):

        """
        Mesma coisa, devolvendo só os pontos.

        A recompensa diminui pela metade
        a cada retransmissão válida.

        Primeira ajuda:
        100

        Segunda:
        50

        Terceira:
        25
        """

        return self.process_return(

            msg_hash,

            helper_key,

            radio

        )["pontos"]




    # =================================================
    # HISTÓRICO DE AJUDANTES
    # =================================================


    def get_helpers(
        self,
        msg_hash
    ):

        """
        Retorna todos os nós que
        retransmitiram uma mensagem.
        """


        entry = self.find(
            msg_hash
        )


        if entry:

            return list(entry["helpers"])


        return []



    def get_rewards(
        self,
        msg_hash
    ):

        """
        Retorna o histórico de recompensas.
        """


        entry = self.find(
            msg_hash
        )


        if entry:

            return list(entry["rewards"])


        return []



    # =================================================
    # VALOR ATUAL
    # =================================================


    def get_value(
        self,
        msg_hash
    ):
        """
        Quanto vale a PRÓXIMA posição desta mensagem.
        """

        entry = self.find(
            msg_hash
        )


        if entry:

            return entry[
                "current_points"
            ]


        return 0


    def get_radio(self, msg_hash):
        """
        Com que SF/BW/CR a mensagem saiu (seção 21).
        """

        entry = self.find(msg_hash)

        return dict(entry["radio"]) if entry and entry["radio"] else None



    # =================================================
    # REMOVER
    # =================================================


    def remove(
        self,
        msg_hash
    ):

        with self.lock:

            if msg_hash in self.entries:

                del self.entries[msg_hash]

                return True

            return False




    # =================================================
    # LIMPAR
    # =================================================


    def clear(self):

        with self.lock:

            self.entries.clear()



    # =================================================
    # LISTAGEM
    # =================================================


    def get_all(self):

        with self.lock:

            return list(self.entries.values())



    def size(self):

        with self.lock:

            return len(self.entries)


    def resumo(self):

        with self.lock:

            proprias = sum(1 for e in self.entries.values() if e["own"])

            return {

                "entradas": len(self.entries),

                "proprias": proprias,

                "retransmitidas": len(self.entries) - proprias,

                "pontos_pagos": round(self.total_pago, 2),

                "descartadas_fifo": self.descartadas

            }



    # =================================================
    # PERSISTÊNCIA
    # =================================================


    def load(self):
        """
        Mensagem sua continua circulando depois que o nó reinicia.
        Sem recuperar a lista, quem devolvesse uma delas não receberia
        nada, e teria gastado antena de graça.
        """

        if not self.storage:

            return False

        try:

            dados = self.storage.load_race()

        except Exception:

            return False

        if not isinstance(dados, list):

            return False

        with self.lock:

            for entry in dados:

                if not isinstance(entry, dict):

                    continue

                msg_hash = entry.get("hash")

                if not msg_hash:

                    continue

                self.entries[msg_hash] = {

                    "hash": msg_hash,

                    "initial_points": float(entry.get("initial_points", 0) or 0),

                    "current_points": float(entry.get("current_points", 0) or 0),

                    "radio": entry.get("radio"),

                    "own": bool(entry.get("own", True)),

                    "created": float(entry.get("created", time.time())),

                    "hits": int(entry.get("hits", 0) or 0),

                    "total_paid": float(entry.get("total_paid", 0) or 0),

                    "helpers": list(entry.get("helpers") or [])[-MAX_HISTORICO:],

                    "rewards": list(entry.get("rewards") or [])[-MAX_HISTORICO:]

                }

            self._aparar()

        return True


    def save(self):

        if not self.storage:

            return False

        with self.lock:

            dados = list(self.entries.values())

        try:

            self.storage.save_race(dados)

            return True

        except Exception:

            return False



# =====================================================
# TESTE
# =====================================================


if __name__ == "__main__":

    RADIO = {"sf": 12, "bw": 250.0, "cr": 7}

    race = RaceList(max_size=5)

    race.add_message("ABC123", 100, radio=RADIO)

    print("=" * 58)
    print(" SEÇÃO 10 - POSIÇÕES DA LISTA DE RECOMPENSA")
    print("=" * 58)
    print("  mensagem ABC123 vale %.0f pontos\n"
          % race.get_value("ABC123"))

    for retorno, quem in enumerate(("B", "C", "B", "D"), start=1):

        r = race.process_return("ABC123", quem, RADIO)

        print("  %do retorno -> %s   %8.2f pontos   (proxima posicao: %.2f)"
              % (retorno, quem, r["pontos"], r["proximo"]))

    print("\n  a mesma carteira ocupou duas posicoes:",
          race.get_helpers("ABC123"))

    print("\n" + "=" * 58)
    print(" SEÇÃO 21 - RETORNO COM OUTRO SF")
    print("=" * 58)

    antes = race.get_value("ABC123")

    r = race.process_return("ABC123", "E", {"sf": 7, "bw": 250.0, "cr": 7})

    print("  pagou?", r["ok"], "|", r["motivo"])
    print("  a posicao continua valendo %.2f (nao foi consumida)"
          % race.get_value("ABC123"))
    print("  valor intacto?", race.get_value("ABC123") == antes)

    print("\n" + "=" * 58)
    print(" SEÇÃO 23 - FIFO")
    print("=" * 58)

    for i in range(6):

        race.add_message("msg_%d" % i, 50, radio=RADIO)

    print("  limite 5, foram inseridas 7 mensagens no total")
    print("  entradas agora:", race.size())
    print("  ABC123 ainda existe?", race.exists("ABC123"))
    print("  resumo:", race.resumo())
