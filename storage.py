#!/usr/bin/env python3

"""
GhostRelay - Storage Manager

Responsabilidade:

- Persistência dos dados do nó
- Salvar estruturas
- Recuperar após reinicialização


Não controla:
- protocolo
- rádio
- assinatura
- economia
"""


import os
import json
import threading
import tempfile



DATA_DIR = "ghostrelay_data"



class Storage:



    def __init__(self):


        self.lock = threading.Lock()


        if not os.path.exists(
            DATA_DIR
        ):

            os.makedirs(
                DATA_DIR
            )



    # =================================================
    # CAMINHO
    # =================================================


    def path(
        self,
        name
    ):

        return os.path.join(

            DATA_DIR,

            name + ".json"

        )



    # =================================================
    # SALVAR
    # =================================================


    def save(
        self,
        name,
        data
    ):


        with self.lock:


            # Escrita atômica:
            # evita corrupção caso o nó desligue
            # durante uma gravação.


            caminho = self.path(name)


            diretorio = os.path.dirname(caminho)


            with tempfile.NamedTemporaryFile(

                "w",

                delete=False,

                dir=diretorio,

                encoding="utf-8"

            ) as f:


                json.dump(

                    data,

                    f,

                    indent=4

                )


                temporario = f.name



            os.replace(

                temporario,

                caminho

            )



    # =================================================
    # CARREGAR
    # =================================================


    def load(
        self,
        name,
        default=None
    ):


        arquivo = self.path(
            name
        )


        if not os.path.exists(
            arquivo
        ):


            return default



        with self.lock:


            with open(

                arquivo,

                "r",

                encoding="utf-8"

            ) as f:


                return json.load(f)



    # =================================================
    # REMOVER
    # =================================================


    def delete(
        self,
        name
    ):


        arquivo = self.path(
            name
        )


        if os.path.exists(
            arquivo
        ):

            os.remove(
                arquivo
            )




    # =================================================
    # ESTADO COMPLETO DO NÓ
    # =================================================


    def save_node_state(
        self,
        state
    ):

        """
        Salva uma visão completa do estado
        do GhostRelay.

        Permite recuperação total:

        - identidade
        - cache
        - vizinhos
        - economia
        - corrida
        - fila
        """


        self.save(

            "node_state",

            state

        )



    def load_node_state(self):

        return self.load(

            "node_state",

            {}

        )



    # =================================================
    # LIMPEZA
    # =================================================


    def clear_all(self):

        """
        Remove todos os dados persistidos.
        Útil para testes e inicialização limpa.
        """


        arquivos = [

            "identity",

            "cache",

            "neighbors",

            "economy",

            "race",

            "relay_queue",

            "node_state"

        ]


        for arquivo in arquivos:

            self.delete(
                arquivo
            )



    # =================================================
    # IDENTITY
    # =================================================


    def save_identity(
        self,
        identity
    ):

        self.save(
            "identity",
            identity
        )



    def load_identity(self):

        return self.load(
            "identity",
            {}
        )



    # =================================================
    # CACHE
    # =================================================


    def save_cache(
        self,
        cache
    ):

        self.save(
            "cache",
            cache
        )



    def load_cache(self):

        return self.load(
            "cache",
            []
        )



    # =================================================
    # VIZINHOS
    # =================================================


    def save_neighbors(
        self,
        neighbors
    ):

        self.save(
            "neighbors",
            neighbors
        )



    def load_neighbors(self):

        return self.load(
            "neighbors",
            {
                "trusted": {},
                "candidates": {}
            }
        )



    # =================================================
    # ECONOMIA
    # =================================================


    def save_economy(
        self,
        economy
    ):

        self.save(
            "economy",
            economy
        )



    def load_economy(self):

        return self.load(
            "economy",
            {}
        )



    # =================================================
    # RACE
    # =================================================


    def save_race(
        self,
        race
    ):

        self.save(
            "race",
            race
        )



    def load_race(self):

        return self.load(
            "race",
            []
        )



    # =================================================
    # RELAY QUEUE
    # =================================================


    def save_queue(
        self,
        queue
    ):

        self.save(
            "relay_queue",
            queue
        )



    def load_queue(self):

        return self.load(
            "relay_queue",
            []
        )


    # Compatibilidade com relay_queue.py

    def save_relay_queue(
        self,
        queue
    ):

        self.save_queue(
            queue
        )


    def load_relay_queue(self):

        return self.load_queue()





# =====================================================
# TESTE
# =====================================================


if __name__ == "__main__":


    storage = Storage()


    storage.save(

        "teste",

        {
            "status":"ok"
        }

    )


    print(
        storage.load(
            "teste"
        )
    )
