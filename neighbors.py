#!/usr/bin/env python3

"""
GhostRelay - Neighbor Manager

Responsabilidade:

- Gerenciar vizinhos conhecidos (trusted)
- Gerenciar candidatos (unknown neighbors)
- Registrar contribuição de candidatos
- Controlar promoção baseada em ajuda real
- Armazenar reputação

Não controla:
- mensagens
- rádio
- cache
- fila


AS DUAS LISTAS
--------------
candidates  vizinhos desconhecidos (seção 18)

    Entra quem mandou um convite válido com uma carteira que eu ainda
    não conhecia. Como convite não é retransmitido, esta lista é
    literalmente "quem eu escuto no meu rádio".

    Candidato não tem pontos. Mensagem vinda dele entra na fila com
    prioridade 10 / tempo (seção 20).

    É um cache FIFO (seção 23): quando lota, o mais antigo sai.


trusted     vizinhos conhecidos (seção 19)

    Entra quem provou utilidade retransmitindo uma mensagem da minha
    lista corrida. Tem pontuação acumulada, que define a prioridade das
    mensagens dele (seção 17) e a prioridade inicial das minhas
    (seção 9).

    Não tem limite de tamanho. A seção 23 cita corrida, candidates e
    fila como caches FIFO, e deixa trusted de fora - faz sentido, é a
    memória econômica do nó. Ela também não cresce sozinha: para entrar
    aqui é preciso gastar tempo de antena carregando mensagem minha.


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) A PROMOÇÃO JOGAVA A RECOMPENSA FORA.

   promote_candidate() criava o vizinho com "points": 0. Mas a seção 19
   diz: "Quando ele retransmite uma mensagem que pertence à sua lista
   corrida, ele é promovido... DEPOIS, recebe os pontos referentes à
   mensagem retransmitida."

   O nó era promovido e ficava zerado. Com zero ponto, a seção 17 dá
   prioridade zero para tudo que ele mandar - ou seja, ele virava
   vizinho conhecido e ficava atrás de qualquer desconhecido, que ao
   menos tem os 10 pontos fixos da seção 20.

2) NINGUÉM CHAMAVA register_relay_help().

   A promoção precisava de três chamadas em sequência, na ordem certa,
   e nenhuma delas acontecia no fluxo real. Agora uma chamada só faz o
   que a seção 19 descreve: registra a ajuda, promove se for candidato
   e credita os pontos.

3) add_trusted() NÃO TIRAVA DE candidates.

   A mesma carteira podia ficar nas duas listas ao mesmo tempo.

4) messages_relayed CRESCIA SEM LIMITE.

   Um nó ligado por dias acumulava um hash por mensagem ajudada, para
   sempre, por vizinho.

5) candidates NÃO TINHA LIMITE.

   A seção 23 diz que é um cache FIFO. Sem limite, qualquer um que
   gerasse carteiras e mandasse convites enchia a memória do nó.

6) SEM PERSISTÊNCIA.

   A reputação sumia a cada reinício, e com ela o sentido da economia:
   o vizinho que gastou antena carregando suas mensagens voltava a ser
   um estranho. (O main.py vinha compensando isso por fora.)

7) SEM PROTEÇÃO ENTRE THREADS.

   A thread que lê o rádio e o laço principal mexem nas mesmas listas.
"""


import threading
import time


# Seção 23 - candidates é um cache FIFO
MAX_CANDIDATES = 256


# Quantos hashes de ajuda guardar por vizinho (histórico, não protocolo)
MAX_HISTORICO = 64


class NeighborManager:


    def __init__(self, storage=None, max_candidates=MAX_CANDIDATES):

        self.trusted_keys = {}

        self.candidates = {}

        self.storage = storage

        self.max_candidates = max_candidates

        self.lock = threading.RLock()

        if self.storage:

            self.load()


    # =================================================
    # CANDIDATOS
    # =================================================


    def add_candidate(self, public_key):
        """
        Seção 18 - convite válido de carteira nova.

        Quando a lista lota, o candidato mais antigo sai (FIFO).
        """

        if not public_key:

            return False

        with self.lock:

            if self.exists(public_key):

                return False


            self.candidates[public_key] = {

                "created": time.time(),

                "status": "candidate",

                "relay_count": 0,

                "messages_relayed": [],

                "last_help": None

            }

            self._aparar_candidatos()

            return True


    def _aparar_candidatos(self):
        """
        Chamado sempre com o lock adquirido.
        Sai o mais antigo, pela ordem de chegada.
        """

        while len(self.candidates) > self.max_candidates:

            mais_antigo = min(

                self.candidates,

                key=lambda k: self.candidates[k]["created"]

            )

            del self.candidates[mais_antigo]



    # =================================================
    # VIZINHO CONHECIDO
    # =================================================


    def add_trusted(self, public_key, points=0):

        if not public_key:

            return False

        with self.lock:

            if public_key in self.trusted_keys:

                return False

            # a mesma carteira não pode ficar nas duas listas
            anterior = self.candidates.pop(public_key, None)

            self.trusted_keys[public_key] = {


                "points": float(points),

                "created": anterior["created"] if anterior else time.time(),

                "status": "trusted",

                "relay_count": anterior["relay_count"] if anterior else 0,

                "messages_relayed": (

                    list(anterior["messages_relayed"]) if anterior else []

                ),

                "last_help": anterior["last_help"] if anterior else None

            }

            return True



    # =================================================
    # EXISTÊNCIA
    # =================================================


    def exists(self, public_key):

        with self.lock:

            return (

                public_key in self.trusted_keys

                or

                public_key in self.candidates

            )



    # =================================================
    # TIPO
    # =================================================


    def get_type(self, public_key):

        with self.lock:

            if public_key in self.trusted_keys:

                return "trusted"


            if public_key in self.candidates:

                return "candidate"


            return None



    # =================================================
    # REGISTRO DE AJUDA
    # =================================================


    def register_relay_help(
        self,
        public_key,
        message_hash,
        points=0
    ):

        """
        Seção 19, na ordem em que ela está escrita:

            candidato retransmite mensagem da minha lista corrida
                    |
                    v
            vira vizinho conhecido
                    |
                    v
            DEPOIS recebe os pontos da mensagem

        Quem valida que a ajuda é real continua sendo quem chama: é o
        main.py que confere se o hash está na lista corrida e se os
        SF/BW/CR batem (seção 21). Este módulo não tem a lista corrida
        e não teria como saber.

        Devolve:

            {
              "promovido": True/False,
              "pontos": creditados agora,
              "total": pontuação do vizinho,
              "ajudas": quantas vezes ele já ajudou
            }

        ou None se a carteira não é conhecida.
        """

        with self.lock:

            promovido = False

            if public_key in self.candidates:

                # a ajuda que motivou a promoção fica registrada antes
                self._registrar_historico(

                    self.candidates[public_key],

                    message_hash

                )

                promovido = self.promote_candidate(public_key)

            elif public_key not in self.trusted_keys:

                return None

            else:

                self._registrar_historico(

                    self.trusted_keys[public_key],

                    message_hash

                )

            node = self.trusted_keys[public_key]

            # "Depois, recebe os pontos referentes à mensagem
            # retransmitida" - antes esta parte se perdia na promoção
            node["points"] += float(points)

            return {

                "promovido": promovido,

                "pontos": float(points),

                "total": node["points"],

                "ajudas": node["relay_count"]

            }


    def _registrar_historico(self, node, message_hash):

        node["relay_count"] += 1

        node["last_help"] = time.time()

        if message_hash:

            historico = node["messages_relayed"]

            historico.append(message_hash)

            # sem isto a lista cresce um hash por ajuda, para sempre
            if len(historico) > MAX_HISTORICO:

                del historico[:-MAX_HISTORICO]



    # =================================================
    # AUTORIZAÇÃO DE PROMOÇÃO
    # =================================================


    def authorize_promotion(
        self,
        public_key,
        message_hash
    ):

        """
        Promoção separada em dois passos, para quem preferir registrar
        a ajuda primeiro e decidir depois.

        O neighbors.py não decide quando
        um candidato merece confiança.

        Ele apenas verifica se existe
        histórico de contribuição.
        """

        with self.lock:

            if public_key not in self.candidates:

                return False



            candidate = self.candidates[public_key]


            if message_hash not in candidate["messages_relayed"]:

                return False



            return self.promote_candidate(
                public_key
            )



    def get_relay_history(
        self,
        public_key
    ):

        """
        Retorna histórico de mensagens
        retransmitidas pelo nó.
        """

        with self.lock:

            if public_key in self.candidates:

                return list(self.candidates[public_key]["messages_relayed"])



            if public_key in self.trusted_keys:

                return list(self.trusted_keys[public_key]["messages_relayed"])



            return []




    # =================================================
    # PROMOVER CANDIDATO
    # =================================================


    def promote_candidate(self, public_key, points=0):
        """
        Seção 19 - vizinho desconhecido vira vizinho conhecido.

        points existe para quem quiser promover e creditar de uma vez.
        Antes esta função zerava a pontuação sem opção.
        """

        with self.lock:

            if public_key not in self.candidates:

                return False



            candidate = self.candidates.pop(
                public_key
            )


            self.trusted_keys[public_key] = {


                "points": float(points),

                "created": candidate["created"],

                "status": "trusted",

                "relay_count": candidate["relay_count"],

                "messages_relayed": candidate["messages_relayed"],

                "last_help": candidate["last_help"]

            }


            return True



    # =================================================
    # PONTOS
    # =================================================


    def get_points(self, public_key):
        """
        Candidato não tem pontuação: ele ainda não provou nada.
        Mensagem dele usa os 10 pontos fixos da seção 20.
        """

        with self.lock:

            if public_key in self.trusted_keys:

                return self.trusted_keys[public_key]["points"]


            return 0



    def add_points(self, public_key, points):

        with self.lock:

            if public_key in self.trusted_keys:

                self.trusted_keys[public_key]["points"] += float(points)

                return True

            return False



    def highest_points(self):
        """
        Seção 9 - a maior pontuação entre os vizinhos.
        A prioridade da mensagem própria é este valor + 1.
        """

        with self.lock:

            if not self.trusted_keys:

                return 0


            return max(

                node["points"]

                for node in self.trusted_keys.values()

            )


    def total_points(self):

        with self.lock:

            return sum(

                node["points"]

                for node in self.trusted_keys.values()

            )



    # =================================================
    # CONSULTAS
    # =================================================


    def get_candidate_data(self, public_key):

        with self.lock:

            return self.candidates.get(
                public_key
            )



    def get_trusted_data(self, public_key):

        with self.lock:

            return self.trusted_keys.get(
                public_key
            )



    def get_candidates(self):

        with self.lock:

            return list(
                self.candidates.keys()
            )



    def get_trusted(self):

        with self.lock:

            return list(
                self.trusted_keys.keys()
            )


    def known_wallets(self):
        """
        Seção 15 - todas as carteiras contra as quais uma assinatura
        deve ser testada, com os conhecidos na frente.
        """

        with self.lock:

            return list(self.trusted_keys.keys()) + list(self.candidates.keys())


    def ranking(self):
        """
        Vizinhos do mais útil para o menos útil.
        """

        with self.lock:

            return sorted(

                (

                    {

                        "chave": chave,

                        "pontos": node["points"],

                        "ajudas": node["relay_count"]

                    }

                    for chave, node in self.trusted_keys.items()

                ),

                key=lambda v: -v["pontos"]

            )


    def resumo(self):

        with self.lock:

            return {

                "conhecidos": len(self.trusted_keys),

                "candidatos": len(self.candidates),

                "pontos_totais": self.total_points(),

                "maior_pontuacao": self.highest_points()

            }



    # =================================================
    # PERSISTÊNCIA
    # =================================================


    def load(self):
        """
        Recupera a reputação depois de um reinício.

        Sem isto o vizinho que gastou antena carregando as suas
        mensagens volta a ser um estranho, e a economia recomeça do
        zero toda vez que o nó liga.
        """

        if not self.storage:

            return False

        try:

            dados = self.storage.load_neighbors()

        except Exception:

            return False

        if not isinstance(dados, dict):

            return False

        with self.lock:

            for chave, node in (dados.get("trusted") or {}).items():

                if isinstance(node, dict):

                    self.trusted_keys[chave] = self._normalizar(node, "trusted")

            for chave, node in (dados.get("candidates") or {}).items():

                if isinstance(node, dict) and chave not in self.trusted_keys:

                    self.candidates[chave] = self._normalizar(node, "candidate")

            self._aparar_candidatos()

        return True


    def _normalizar(self, node, status):
        """
        Aceita entrada gravada por versões anteriores sem quebrar.
        """

        historico = node.get("messages_relayed") or []

        if not isinstance(historico, list):

            historico = []

        return {

            "points": float(node.get("points", 0) or 0),

            "created": float(node.get("created", time.time()) or time.time()),

            "status": status,

            "relay_count": int(node.get("relay_count", 0) or 0),

            "messages_relayed": historico[-MAX_HISTORICO:],

            "last_help": node.get("last_help")

        }


    def save(self):

        if not self.storage:

            return False

        with self.lock:

            dados = {

                "trusted": dict(self.trusted_keys),

                "candidates": dict(self.candidates)

            }

        try:

            self.storage.save_neighbors(dados)

            return True

        except Exception:

            return False



    # =================================================
    # REMOVER
    # =================================================


    def remove(self, public_key):

        with self.lock:

            achou = False

            if public_key in self.candidates:

                del self.candidates[public_key]

                achou = True


            if public_key in self.trusted_keys:

                del self.trusted_keys[public_key]

                achou = True

            return achou


# =====================================================
# TESTE DO MÓDULO
# =====================================================

if __name__ == "__main__":

    viz = NeighborManager()

    A = "carteira_A"
    B = "carteira_B"

    print("=" * 58)
    print(" SEÇÕES 18 E 19 - DO CONVITE À CONFIANÇA")
    print("=" * 58)

    viz.add_candidate(A)

    print("  convite de A     -> %s, %.0f pontos"
          % (viz.get_type(A), viz.get_points(A)))

    print("  convite repetido -> registrado de novo?", viz.add_candidate(A))

    resultado = viz.register_relay_help(A, "hash_da_mensagem", points=100)

    print("\n  A retransmitiu uma mensagem da minha lista corrida:")
    print("    promovido      :", resultado["promovido"])
    print("    pontos agora   : %.0f" % resultado["pontos"])
    print("    total          : %.0f" % resultado["total"])
    print("    tipo           :", viz.get_type(A))

    viz.register_relay_help(A, "outro_hash", points=50)

    print("\n  segunda ajuda    -> total %.0f pontos" % viz.get_points(A))

    viz.add_candidate(B)
    viz.register_relay_help(B, "hash_3", points=500)

    print("\n" + "=" * 58)
    print(" SEÇÃO 9 - PRIORIDADE DA MENSAGEM PRÓPRIA")
    print("=" * 58)

    for v in viz.ranking():

        print("  %-12s %8.0f pontos | %d ajudas"
              % (v["chave"], v["pontos"], v["ajudas"]))

    print("\n  maior pontuação: %.0f" % viz.highest_points())
    print("  prioridade de uma mensagem minha: %.0f"
          % (viz.highest_points() + 1))

    print("\n  resumo:", viz.resumo())
