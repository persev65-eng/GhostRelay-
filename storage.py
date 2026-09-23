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


O QUE MORA AQUI DENTRO
----------------------
    identity     a chave privada do nó (seção 2)
    neighbors    a reputação dos vizinhos (seções 9, 17 e 19)
    race         a lista corrida com as mensagens em circulação
    cache        os hashes já vistos (seção 6)

A pasta guarda a identidade do nó. Perder ou expor esse diretório é
perder ou entregar a carteira: a chave privada "permanece somente no
próprio dispositivo" (seção 2).


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) A CHAVE PRIVADA FICAVA LEGÍVEL PARA QUALQUER USUÁRIO DA MÁQUINA.

   Os arquivos eram gravados com a permissão padrão do sistema. O
   identity.py tinha o cuidado de usar 0600 no arquivo legado, mas ao
   gravar pelo storage essa proteção se perdia - e é justamente o
   caminho preferido. Agora a pasta é 0700 e todo arquivo é 0600.

2) A PASTA DEPENDIA DE ONDE VOCÊ ESTAVA NO TERMINAL.

   DATA_DIR era um caminho relativo. Rodar o nó de outro diretório
   criava uma pasta nova e vazia: carteira diferente, reputação
   zerada, candidatos perdidos. O nó virava outro nó.

   Agora a pasta fica junto do código, com ordem de preferência:
   parâmetro > variável GHOST_DATA > pasta já existente no diretório
   atual (compatibilidade) > pasta do código.

3) ARQUIVO CORROMPIDO DERRUBAVA O NÓ.

   load() chamava json.load direto. Um arquivo truncado ou editado à
   mão levantava exceção na inicialização. Agora ele é preservado com
   outro nome e o nó sobe com o padrão, em vez de não subir.

4) A GRAVAÇÃO "ATÔMICA" NÃO CHEGAVA AO DISCO.

   os.replace troca o arquivo de forma atômica, mas sem flush e fsync
   o conteúdo pode ainda estar em cache quando a energia cai - que é
   exatamente o cenário que o comentário dizia proteger.

5) ARQUIVO TEMPORÁRIO VAZAVA.

   Com delete=False, se o json.dump falhasse (objeto não serializável,
   disco cheio), o temporário ficava na pasta para sempre e o
   os.replace nunca acontecia.

6) DUAS INSTÂNCIAS DE Storage USAVAM LOCKS DIFERENTES.

   O lock era por instância. Dois objetos apontando para o mesmo
   arquivo podiam gravar ao mesmo tempo. Agora o lock é por caminho.

7) load_identity() DEVOLVIA {} QUANDO NÃO HAVIA NADA.

   A identidade é uma string; um dicionário vazio no lugar dela é um
   tipo que ninguém espera.
"""


import json
import os
import stat
import tempfile
import threading


PASTA_PADRAO = "ghostrelay_data"


# Um lock por caminho de arquivo, compartilhado por todas as instâncias
# de Storage. Antes o lock era por objeto, e dois Storage apontando para
# o mesmo arquivo não se enxergavam.
_locks = {}

_locks_lock = threading.Lock()


def _lock_do_arquivo(caminho):

    with _locks_lock:

        if caminho not in _locks:

            _locks[caminho] = threading.RLock()

        return _locks[caminho]


def _pasta_de_dados(pasta=None):
    """
    Ordem de preferência:

    1 - o que foi passado no construtor
    2 - a variável de ambiente GHOST_DATA
    3 - uma pasta ghostrelay_data já existente no diretório atual
        (para não perder os dados de quem já estava rodando assim)
    4 - ao lado do código

    O caso 4 é o que evita o nó trocar de identidade só porque você
    rodou o main.py de outro diretório.
    """

    if pasta:

        return os.path.abspath(pasta)

    do_ambiente = os.environ.get("GHOST_DATA")

    if do_ambiente:

        return os.path.abspath(do_ambiente)

    no_diretorio_atual = os.path.abspath(PASTA_PADRAO)

    if os.path.isdir(no_diretorio_atual):

        return no_diretorio_atual

    return os.path.join(

        os.path.dirname(os.path.abspath(__file__)),

        PASTA_PADRAO

    )


# Mantido por compatibilidade com quem importava a constante
DATA_DIR = PASTA_PADRAO


class Storage:


    def __init__(self, pasta=None):

        self.dir = _pasta_de_dados(pasta)

        if not os.path.exists(
            self.dir
        ):

            os.makedirs(
                self.dir,
                exist_ok=True
            )

        # a pasta guarda a chave privada: ninguém além do dono entra
        self._proteger(self.dir, dono_apenas_pasta=True)

        # compatibilidade: alguns módulos liam storage.lock
        self.lock = _lock_do_arquivo(self.dir)


    def __repr__(self):

        return "<Storage %s>" % self.dir


    @staticmethod
    def _proteger(caminho, dono_apenas_pasta=False):
        """
        Pasta 0700, arquivo 0600. Em sistemas sem permissão POSIX
        (Windows), simplesmente não faz nada.
        """

        try:

            if dono_apenas_pasta:

                os.chmod(caminho, stat.S_IRWXU)

            else:

                os.chmod(caminho, stat.S_IRUSR | stat.S_IWUSR)

        except OSError:

            pass


    # =================================================
    # CAMINHO
    # =================================================


    def path(
        self,
        name
    ):

        return os.path.join(

            self.dir,

            name + ".json"

        )


    def existe(self, name):

        return os.path.exists(self.path(name))



    # =================================================
    # SALVAR
    # =================================================


    def save(
        self,
        name,
        data
    ):


        caminho = self.path(name)

        with _lock_do_arquivo(caminho):


            # Escrita atômica:
            # evita corrupção caso o nó desligue
            # durante uma gravação.


            diretorio = os.path.dirname(caminho)


            temporario = None

            try:

                with tempfile.NamedTemporaryFile(

                    "w",

                    delete=False,

                    dir=diretorio,

                    encoding="utf-8"

                ) as f:


                    temporario = f.name

                    json.dump(

                        data,

                        f,

                        indent=2

                    )

                    # sem isto o conteúdo pode estar só no cache do
                    # sistema quando a energia cair, e o arquivo novo
                    # aparece vazio
                    f.flush()

                    os.fsync(f.fileno())


                self._proteger(temporario)

                os.replace(

                    temporario,

                    caminho

                )

                temporario = None

                return True

            finally:

                # dump falhou no meio: não deixa lixo na pasta
                if temporario and os.path.exists(temporario):

                    try:

                        os.remove(temporario)

                    except OSError:

                        pass



    # =================================================
    # CARREGAR
    # =================================================


    def load(
        self,
        name,
        default=None
    ):


        caminho = self.path(
            name
        )


        with _lock_do_arquivo(caminho):


            if not os.path.exists(
                caminho
            ):


                return default


            try:

                with open(

                    caminho,

                    "r",

                    encoding="utf-8"

                ) as f:


                    return json.load(f)


            except (ValueError, OSError) as erro:

                # arquivo truncado ou editado à mão não pode impedir o
                # nó de subir; guarda para análise e segue com o padrão
                print("[STORAGE] %s ilegivel (%s)" % (name, erro))

                self._preservar(caminho)

                return default


    @staticmethod
    def _preservar(caminho):

        destino = caminho + ".corrompido"

        try:

            os.replace(caminho, destino)

            print("[STORAGE] arquivo movido para", destino)

        except OSError:

            pass



    # =================================================
    # REMOVER
    # =================================================


    def delete(
        self,
        name
    ):


        caminho = self.path(
            name
        )


        with _lock_do_arquivo(caminho):

            if os.path.exists(
                caminho
            ):

                os.remove(
                    caminho
                )

                return True

            return False




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

        ATENÇÃO: isto apaga a carteira do nó. Ele volta com outra
        identidade, e toda a reputação que os vizinhos tinham com ele
        deixa de valer (seções 18 e 19: precisa mandar convite e ser
        promovido de novo).
        """


        arquivos = [

            "identity",

            "cache",

            "neighbors",

            "economy",

            "race",

            "relay_queue",

            "contacts",

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
        """
        A identidade é uma string (semente em base64).
        O padrão é None, não um dicionário vazio.
        """

        return self.load(
            "identity",
            None
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



    # =================================================
    # DIAGNÓSTICO
    # =================================================


    def resumo(self):
        """
        O que está gravado e quanto ocupa.
        """

        itens = {}

        try:

            arquivos = sorted(os.listdir(self.dir))

        except OSError:

            return {"pasta": self.dir, "erro": "pasta ilegivel"}

        for arquivo in arquivos:

            if not arquivo.endswith(".json"):

                continue

            caminho = os.path.join(self.dir, arquivo)

            try:

                itens[arquivo[:-5]] = os.path.getsize(caminho)

            except OSError:

                pass

        return {

            "pasta": self.dir,

            "arquivos": itens

        }




# =====================================================
# TESTE
# =====================================================


if __name__ == "__main__":


    storage = Storage()

    print("pasta de dados:", storage.dir)


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

    modo_pasta = stat.S_IMODE(os.stat(storage.dir).st_mode)

    modo_arquivo = stat.S_IMODE(os.stat(storage.path("teste")).st_mode)

    print("permissao da pasta  :", oct(modo_pasta), "(esperado 0o700)")

    print("permissao do arquivo:", oct(modo_arquivo), "(esperado 0o600)")

    print("resumo:", storage.resumo())

    storage.delete("teste")
