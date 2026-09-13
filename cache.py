"""
GhostRelay - Cache de Memória FIFO

Responsabilidade:
- Guardar hashes de mensagens já vistas
- Evitar loops de retransmissão
- Servir como memória temporária da rede

Regras (seções 6 e 14 do protocolo):
- O hash é calculado APENAS da mensagem
- Não inclui assinatura
- Não inclui marcador <0>
- FIFO: quando lotar, remove o mais antigo
- Hash já existe  -> descarta a mensagem
- Hash não existe -> registra e continua o processamento


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) add() guardava um dicionário {"hash":..., "timestamp":...} e exists()
   procurava por uma string. A comparação nunca dava certo, então o cache
   JAMAIS detectava duplicata: a seção 6 (anti-loop) estava desligada e a
   memória enchia de repetidos.

2) A troca do deque por OrderedDict resolve os dois lados de uma vez:
   busca em tempo constante (antes era varredura linear em até 1000 itens
   a cada pacote recebido) e ordem de inserção preservada, que é
   exatamente o FIFO que a seção 6 pede.

3) save_storage() era chamado a cada add(), ou seja, regravava o arquivo
   inteiro a cada pacote recebido. Agora a gravação é espaçada no tempo.
   IMPORTANTE: chame flush() ao encerrar o nó para não perder o resto.

4) O cache é tocado por mais de uma thread (a leitora da serial e o laço
   principal). check_and_register() agora é atômico: consultar e
   registrar acontecem sob o mesmo lock, senão duas threads podem
   considerar a mesma mensagem "nova" ao mesmo tempo.

5) load_storage() aceita tanto o formato antigo (lista de dicionários)
   quanto o novo (lista de hashes), para não perder a memória de um nó
   que já estava rodando.
"""


from collections import OrderedDict
import hashlib
import threading
import time


try:

    from storage import Storage

except Exception:

    Storage = None


# Marcador de fim de transmissão (seção 4).
# Fica aqui só para a checagem de sanidade de mensagem_pura().
END_MARKER = "<0>"


# Intervalo mínimo entre gravações no disco, em segundos
SAVE_INTERVAL = 5.0


class GhostCache:

    def __init__(
        self,
        max_size=1000,
        storage=None,
        save_interval=SAVE_INTERVAL
    ):
        """
        Cria o cache FIFO.

        O cache mantém memória em RAM
        e sincroniza com storage.py.

        max_size:
            quantidade máxima de hashes armazenados

        storage:
            instância de Storage (opcional)

        save_interval:
            segundos entre gravações em disco
        """

        self.max_size = max(1, int(max_size))

        # hash -> timestamp
        # OrderedDict preserva a ordem de chegada: o primeiro a entrar
        # é o primeiro a sair, sem depender de tempo de expiração.
        self.memory = OrderedDict()

        self.storage = storage

        self.save_interval = save_interval

        self.lock = threading.RLock()

        self._pendente = False

        self._ultimo_save = 0.0

        # estatísticas úteis para diagnóstico
        self.total_novos = 0

        self.total_duplicados = 0

        self.total_descartados = 0

        if self.storage:

            self.load_storage()


    # =================================================
    # STORAGE
    # =================================================


    def load_storage(self):
        """
        Recupera hashes persistidos
        após reinicialização do nó.

        Aceita o formato antigo (lista de dicionários)
        e o novo (lista de hashes).
        """

        if not self.storage:

            return

        try:

            data = self.storage.load_cache()

        except Exception:

            return

        if not data:

            return

        with self.lock:

            for item in data:

                # formato novo: "abc123..."
                if isinstance(item, str):

                    message_hash = item

                    timestamp = time.time()

                # formato antigo: {"hash": "...", "timestamp": ...}
                elif isinstance(item, dict):

                    message_hash = item.get("hash")

                    timestamp = item.get("timestamp", time.time())

                else:

                    continue

                if not message_hash:

                    continue

                self.memory[message_hash] = timestamp

            self._aparar()


    def save_storage(self, force=False):
        """
        Salva o estado atual do cache.

        A gravação é espaçada: sem isso o nó reescreveria
        o arquivo inteiro a cada pacote que chega.
        """

        if not self.storage:

            return

        agora = time.time()

        with self.lock:

            self._pendente = True

            if not force:

                if agora - self._ultimo_save < self.save_interval:

                    return

            dados = list(self.memory.keys())

            self._ultimo_save = agora

            self._pendente = False

        try:

            self.storage.save_cache(dados)

        except Exception:

            # disco cheio ou permissão negada não podem derrubar o nó:
            # o cache continua válido em RAM
            with self.lock:

                self._pendente = True


    def flush(self):
        """
        Força a gravação imediata.

        Deve ser chamado ao encerrar o nó,
        senão os últimos hashes se perdem.
        """

        self.save_storage(force=True)


    # =================================================
    # GERAR HASH DA MENSAGEM
    # =================================================

    @staticmethod
    def generate_hash(message):
        """
        Gera o hash da mensagem (seções 5 e 14).

        IMPORTANTE:
        Recebe somente a mensagem pura.

        NÃO deve receber:
        - assinatura
        - <0>

        É esse recorte que faz o hash sobreviver à troca de assinatura
        da seção 16: o mesmo conteúdo gera o mesmo hash em todos os nós,
        mesmo cada um assinando com a própria carteira.
        """

        if isinstance(message, bytes):

            dados = message

        else:

            dados = str(message).encode("utf-8")

        return hashlib.sha256(dados).hexdigest()


    @staticmethod
    def mensagem_pura(message):
        """
        Sanidade: devolve False se a mensagem ainda tiver o marcador
        de fim colado nela, sinal de que o pacote não foi separado antes
        de gerar o hash.

        Serve para o message.py conferir antes de chamar o cache.
        Hash calculado sobre o pacote inteiro nunca bate entre dois nós
        e desliga silenciosamente o anti-loop e a economia.
        """

        if isinstance(message, bytes):

            return not message.endswith(END_MARKER.encode())

        return not str(message).endswith(END_MARKER)


    # =================================================
    # VERIFICAR EXISTÊNCIA
    # =================================================

    def exists(self, message_hash):
        """
        Verifica se a mensagem já passou pelo nó.

        Retorna:
            True  -> já existe
            False -> mensagem nova
        """

        if not message_hash:

            return False

        with self.lock:

            return message_hash in self.memory


    # =================================================
    # ADICIONAR HASH
    # =================================================

    def add(self, message_hash):
        """
        Adiciona um hash ao cache.

        Quando o cache lota, o mais antigo sai (FIFO).

        Retorna:
            True  -> era novo e foi registrado
            False -> já existia
        """

        if not message_hash:

            return False

        with self.lock:

            if message_hash in self.memory:

                return False

            self.memory[message_hash] = time.time()

            self.total_novos += 1

            self._aparar()

        self.save_storage()

        return True


    def _aparar(self):
        """
        Aplica o limite FIFO.

        Chamado sempre com o lock já adquirido.
        """

        while len(self.memory) > self.max_size:

            self.memory.popitem(last=False)

            self.total_descartados += 1


    # =================================================
    # PROCESSAMENTO PRINCIPAL
    # =================================================

    def check_and_register(self, message):
        """
        Função principal usada pelo protocolo (seção 14).

        Recebe:
            mensagem pura

        Faz:
            1 - gera hash
            2 - verifica memória
            3 - registra se for nova

        Consulta e registro acontecem sob o mesmo lock,
        senão duas threads podem achar que a mesma mensagem é nova.

        Retorno:

            {
              "new": True/False,
              "hash": hash
            }

        new = False  -> descarte a mensagem (seções 6 e 14)
        new = True   -> siga o processamento
        """

        message_hash = self.generate_hash(message)

        with self.lock:

            if message_hash in self.memory:

                self.total_duplicados += 1

                return {

                    "new": False,

                    "hash": message_hash

                }

            self.memory[message_hash] = time.time()

            self.total_novos += 1

            self._aparar()

        self.save_storage()

        return {

            "new": True,

            "hash": message_hash

        }


    # =================================================
    # INFORMAÇÕES
    # =================================================

    def size(self):

        with self.lock:

            return len(self.memory)


    def clear(self):

        with self.lock:

            self.memory.clear()

        self.save_storage(force=True)


    def get_all(self):
        """
        Lista de hashes, do mais antigo para o mais novo.
        """

        with self.lock:

            return list(self.memory.keys())


    def get_details(self):
        """
        Mesma lista, com o instante em que cada hash entrou.
        """

        with self.lock:

            return [

                {
                    "hash": h,
                    "timestamp": t
                }

                for h, t in self.memory.items()

            ]


    def stats(self):
        """
        Diagnóstico do anti-loop.

        duplicados alto é sinal de que a rede está circulando
        mensagem de volta, que é justamente o que o cache existe
        para cortar.
        """

        with self.lock:

            return {

                "tamanho": len(self.memory),

                "limite": self.max_size,

                "novos": self.total_novos,

                "duplicados": self.total_duplicados,

                "descartados_fifo": self.total_descartados

            }


# =====================================================
# TESTE DO MÓDULO
# =====================================================

if __name__ == "__main__":

    cache = GhostCache(max_size=5)

    mensagem = "OLA_GHOSTRELAY"

    print("Primeira mensagem:")

    print(cache.check_and_register(mensagem))

    print("\nSegunda tentativa (tem que vir new=False):")

    print(cache.check_and_register(mensagem))

    print("\nSimulando o loop da seção 6 (A -> B -> C -> A):")

    # cada nó tem o SEU próprio cache
    nos = {

        "A": GhostCache(max_size=100),

        "B": GhostCache(max_size=100),

        "C": GhostCache(max_size=100)

    }

    # A cria a mensagem: o hash já entra no cache dele (seção 5)
    nos["A"].check_and_register(mensagem)

    print("   nó A cria a mensagem e guarda o hash")

    for no in ("B", "C", "A"):

        r = nos[no].check_and_register(mensagem)

        if r["new"]:

            print("   nó %s recebe -> novo, retransmite" % no)

        else:

            print("   nó %s recebe -> JÁ VISTO, descarta (loop cortado)" % no)

    print("\nFIFO: enchendo o cache (limite 5):")

    for i in range(7):

        cache.add("hash_%d" % i)

    print("   guardados:", cache.get_all())

    print("   hash_0 ainda existe?", cache.exists("hash_0"))

    print("   hash_6 existe?      ", cache.exists("hash_6"))

    print("\nEstatísticas:")

    print("  ", cache.stats())
