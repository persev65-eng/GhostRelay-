#!/usr/bin/env python3

"""
CONFIRMAÇÃO DE ENTREGA - COMO O NÓ FUNCIONA AGORA
-------------------------------------------------
Só o autor paga, e só mensagem própria entra na lista corrida.

  autor         cifra para o contato, abre DUAS corridas de mesmo valor
  relay         não lê, reassina, retransmite; não paga ninguém
  destinatário  abre, entrega ao app, devolve a confirmação (hash do
                texto cifrado para o autor); não retransmite a mensagem
                e não paga quem carregar a confirmação
  autor         ao receber a primeira confirmação: libera a corrida da
                ida (retida até aqui), credita o destinatário em
                CONTATOS com o valor da mensagem, e paga a corrida da
                volta a cada cópia da confirmação que chegar

Prioridade da confirmação, no destinatário:
    max(1, pontos do contato) x tempo da mensagem / tempo da confirmação

GhostRelay - Main Controller

Responsabilidade:

- Inicializar todos os módulos
- Coordenar comunicação entre camadas
- Encaminhar eventos do MAC
- Manter o nó ativo

Não contém:
- criptografia
- hash
- economia
- regras de vizinhos
- protocolo de mensagem

Ele não CALCULA nada: ele decide a ORDEM em que os módulos são
chamados. Essa ordem é o que as seções 5 e 13 a 21 descrevem.


O FLUXO DE RECEPÇÃO (seções 13 a 21)
------------------------------------
    1  separar [MENSAGEM][ASSINATURA] do <0>        seção 13
    2  calcular o hash só da mensagem               seção 14
    3  é convite?  -> vizinho desconhecido          seções 12 e 18
    4  está na minha lista corrida?                 seções 10, 19 e 21
       -> pagar quem retransmitiu e parar aqui
    5  já está no cache? -> descartar                seções 6 e 14
    6  a assinatura é de alguma carteira conhecida?  seção 15
       -> se não for, descartar
    7  registrar no cache
    8  calcular prioridade                           seções 17 e 20
    9  trocar a assinatura pela minha                seção 16
   10  entrar na lista corrida                       seção 20, item 6
   11  enfileirar com os MESMOS SF/BW/CR             seção 21
   12  entregar o texto para a aplicação


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) A RECEPÇÃO NÃO EXISTIA.

   process_mac_event() tratava "RX_DONE", mas nada nunca colocava
   RX_DONE em mac_events. O caminho de recepção inteiro era código
   morto: nenhuma mensagem recebida chegava ao protocolo.

2) O NÓ RETRANSMITIA A MESMA MENSAGEM PARA SEMPRE.

   process_relay_queue() chamava mac.transmitir() a cada volta do laço
   e NUNCA chamava mark_transmitted(). Como o get_next() da relay_queue
   também não remove o item, a mesma mensagem de maior prioridade era
   transmitida infinitamente, ocupando o canal sozinha. Agora a fila é
   entregue ao MAC (attach_relay_queue) e quem transmite é só ele.

3) A LISTA CORRIDA NUNCA FOI LIGADA.

   race.py não era nem importado. Sem ele não há recompensa (seção 10)
   nem promoção de candidato (seção 19): a economia do documento
   simplesmente não existia no nó em execução.

4) O CONVITE NUNCA ERA CRIADO.

   Sem convite ninguém entra em candidates, ninguém é promovido, e a
   rede não se forma (seções 12 e 18). Agora o nó anuncia a carteira,
   de forma periódica ou manual, como o dono do nó preferir.

   Convite recebido NÃO é retransmitido e NÃO entra no cache: ele é um
   anúncio de vizinhança direta, e quem controla repetição dele é a
   lista de vizinhos.

5) O SERVIDOR NUNCA SUBIA.

   main.py importava obter_mensagem_tx() do server.py mas nunca
   iniciava o servidor. Rodar server.py à parte também não resolvia:
   seria outro processo, com outra fila, que ninguém lê. Agora o
   main.py sobe o servidor dentro do próprio nó.

6) GhostMessage era criado SEM neighbors, então process_invite() não
   conseguia registrar candidato nenhum (seção 18).

7) O laço principal ficava até 1 segundo parado em mac_events.get(),
   e mensagens da aplicação esperavam essa volta inteira.

8) UMA MENSAGEM IMPOSSÍVEL DE TRANSMITIR TRAVAVA O NÓ INTEIRO.

   Quando o rádio não consegue aplicar o SF/BW/CR de uma mensagem, a
   transmissão é cancelada (seção 21). Só que falha não desconta
   prioridade - a seção 11 só desconta quando transmite. Resultado: a
   mensagem ficava eternamente no topo da fila, o MAC escolhia,
   falhava, escolhia de novo, e o nó parava de transmitir qualquer
   outra coisa.

   Medido com o firmware antigo: uma única mensagem nessa situação
   levou a vazão do nó a ZERO pacote no ar. Agora ela sai da fila e,
   se for própria, a aplicação é avisada.

9) CONVITE IGNORADO NÃO ENTRAVA NA CONTA DE DESCARTADOS.


RETRANSMISSÃO REPETIDA (seções 10 e 11)
---------------------------------------
Um nó pode retransmitir a mesma mensagem quantas vezes quiser, e isso é
desejado: aumenta a chance de a mensagem alcançar alguém.

O equilíbrio vem da economia, não de um limite artificial. Cada retorno
de uma mensagem ocupa uma posição na lista de recompensa dela, e cada
posição vale metade da anterior -- independente de quem retornou. A
mesma carteira pode ocupar várias posições. Então repetir rende cada vez
menos pelo mesmo custo de antena, e a decisão de parar é de quem repete.

Do lado de quem transmite, a seção 11 corta a prioridade pela metade a
cada transmissão e a seção 3.3 dobra a janela de espera do MAC: o nó
falador vai naturalmente ficando mais paciente e mais para o fim da fila.
"""


import os
import signal
import sys
import threading
import time


# =====================================================
# IMPORTS DOS MÓDULOS GHOSTRELAY
# =====================================================


from identity import GhostIdentity

from cache import GhostCache

from economy import GhostEconomy


try:

    from storage import Storage

except Exception:

    Storage = None


try:

    from neighbors import NeighborManager

except Exception:

    NeighborManager = None


try:

    from relay_queue import RelayQueue

except Exception:

    RelayQueue = None


try:

    from message import GhostMessage

except Exception:

    GhostMessage = None


try:

    from contacts import ContactBook

except Exception as erro:

    print("contacts.py indisponivel:", erro)

    ContactBook = None


try:

    from race import RaceList

except Exception:

    RaceList = None


try:

    from mac import Radio, GhostRelayMAC, mac_events, LISTEN_CONFIG

except Exception as _erro_mac:

    Radio = None
    GhostRelayMAC = None
    mac_events = None
    LISTEN_CONFIG = {"sf": 12, "bw": 250.0, "cr": 7}


# o server.py é importado como módulo para o nó poder subi-lo
try:

    import server as servidor_app

except Exception:

    servidor_app = None


# =====================================================
# CONFIGURAÇÃO
# =====================================================


NODE_NAME = "GHOSTRELAY_NODE"


# Seção 12: o convite é o único jeito de um nó novo ser descoberto.
#
# Como anunciar a carteira é escolha do dono do nó:
#
#   "periodico"  anuncia ao ligar e de tempos em tempos
#   "manual"     só anuncia quando a aplicação pedir
#
# Em qualquer um dos modos a aplicação pode disparar um convite na
# hora, mandando {"tipo":"convite"} ou o texto /convite pelo WebSocket.
CONVITE_MODO = "periodico"

INTERVALO_CONVITE = 300          # s   (usado só no modo periódico)


# Seções 11 e 23: a mensagem NÃO sai da fila por ter sido transmitida
# um número de vezes. Ela fica, com a prioridade caindo pela metade a
# cada transmissão, e só sai por FIFO quando a fila lota. Retransmitir
# a mesma mensagem várias vezes é parte do protocolo: é o que aumenta a
# chance de ela atravessar a rede. Quem repete demais é freado pela
# própria prioridade (que despenca) e pela janela de backoff do MAC,
# que dobra a cada transmissão bem-sucedida (seção 3.3).
#
# PRIORIDADE_MINIMA acima de zero tira da fila o que já não compete com
# nada. Fica em zero por padrão, que é o comportamento do documento;
# suba para 0.01 se um nó sozinho na rede estiver repetindo a mesma
# mensagem sem parar.
PRIORIDADE_MINIMA = 0.0


# Só o autor paga, e só mensagem PRÓPRIA entra na lista corrida (seção 7).
# Se relay pagasse relay, o autor ganharia pontos infinitos: B registra
# a mensagem de A na corrida dele, A repete, e B paga A pela mensagem do
# próprio A. A constante que ligava isso saiu.

# O destinatário também retransmite a mensagem que era para ele?
# Não retransmitir economiza antena (ela já chegou). Retransmitir esconde
# melhor quem é o destinatário, porque ele se comporta como um relay.
DESTINATARIO_RETRANSMITE = False


INTERVALO_MANUTENCAO = 10        # s

INTERVALO_SALVAR = 30            # s


# =====================================================
# CLASSE PRINCIPAL
# =====================================================


class GhostRelayNode:


    def __init__(self):

        print(
            """
============================
 GHOSTRELAY START
============================
"""
        )

        self.rodando = True

        self.ultimo_convite = 0.0

        self.ultima_manutencao = 0.0

        self.ultimo_salvar = 0.0

        self.stats = {

            "recebidos": 0,

            "descartados": 0,

            "retransmitidos": 0,

            "proprias": 0,

            "convites_rx": 0,

            "pontos_pagos": 0.0,

            "entregues": 0,

            "confirmacoes_enviadas": 0,

            "confirmacoes_recebidas": 0

        }

        # -------------------------
        # STORAGE
        # -------------------------

        self.storage = None

        if Storage:

            try:

                self.storage = Storage()

            except Exception as erro:

                print("Storage indisponivel:", erro)

        # -------------------------
        # IDENTIDADE
        # -------------------------

        print("Carregando identidade...")

        self.identity = GhostIdentity(storage=self.storage)

        print("PUBLIC KEY:")

        print(self.identity.get_public_key())

        # -------------------------
        # CACHE
        # -------------------------

        self.contacts = None

        if ContactBook:

            print("Iniciando contatos...")

            self.contacts = ContactBook(storage=self.storage)

        print("Iniciando cache...")

        self.cache = GhostCache(

            max_size=1000,

            storage=self.storage

        )

        # -------------------------
        # ECONOMIA
        # -------------------------

        print("Iniciando economia...")

        self.economy = GhostEconomy()

        # -------------------------
        # VIZINHOS
        # -------------------------

        self.neighbors = None

        if NeighborManager:

            print("Iniciando vizinhos...")

            self.neighbors = NeighborManager(storage=self.storage)

        # -------------------------
        # LISTA CORRIDA (seção 7)
        # -------------------------

        self.race = None

        if RaceList:

            print("Iniciando lista corrida...")

            self.race = RaceList(storage=self.storage)

        else:

            print("AVISO: race.py ausente - sem recompensa (secoes 10 e 19)")

        # -------------------------
        # FILA
        # -------------------------

        self.queue = None

        if RelayQueue:

            print("Iniciando fila...")

            self.queue = RelayQueue()

        # -------------------------
        # PROCESSADOR DE MENSAGEM
        # -------------------------

        self.messages = None

        if GhostMessage:

            print("Iniciando mensagens...")

            # antes ia sem neighbors, e sem isso a seção 18 não funciona
            self.messages = GhostMessage(

                self.identity,

                self.cache,

                self.neighbors

            )

        # -------------------------
        # MAC
        # -------------------------

        self.radio = None

        self.mac = None

        if Radio and GhostRelayMAC:

            print("Iniciando MAC...")

            try:

                self.radio = Radio()

                self.mac = GhostRelayMAC(self.radio)

                # a fila de prioridade é quem manda no que vai ao ar:
                # o MAC consome dela e avisa mark_transmitted (seção 11)
                if self.queue:

                    self.mac.attach_relay_queue(self.queue)

            except Exception as erro:

                print("RADIO INDISPONIVEL:", erro)

                print("o no vai subir sem transmitir (modo de teste)")

                self.radio = None

                self.mac = None

        print(
            """
============================
 GHOSTRELAY ONLINE
============================
"""
        )

    # =================================================
    # CONFIGURAÇÃO DE RÁDIO DO NÓ
    # =================================================

    def radio_padrao(self):
        """
        SF/BW/CR com que este nó escuta e cria as próprias mensagens.
        Antes era 12/250/7 escrito na mão dentro do fluxo.
        """

        if self.radio:

            return dict(self.radio.listen_config)

        return dict(LISTEN_CONFIG)

    # =================================================
    # VIZINHOS: CARTEIRAS CONHECIDAS
    # =================================================

    def pontos_do_vizinho(self, chave):

        if not self.neighbors:

            return 0

        return self.neighbors.get_points(chave)

    def salvar_vizinhos(self):

        if self.neighbors:

            self.neighbors.save()


    # =================================================
    # PROCESSAMENTO DE MENSAGEM DA APLICAÇÃO
    # =================================================

    def process_application_message(self, data):
        """
        Seções 5 e 22. A aplicação manda:

            {"tipo": "tx", "dados": "texto", "para": "<chave ou nome>"}
            {"tipo": "contato", "chave": "...", "nome": "...",
             "categoria": "pessoa" | "site"}
            {"tipo": "remover_contato", "chave": "..."}
            {"tipo": "contatos"}
            {"tipo": "convite"}

        Toda mensagem tem destinatário: ela vai cifrada para ele.
        """

        if not data or not self.messages:

            return

        para = ""

        if isinstance(data, dict):

            tipo = str(data.get("tipo") or data.get("type") or "tx").lower()

            if tipo in ("convite", "invite"):

                return self.criar_convite()

            if tipo in ("contato", "contact"):

                return self.registrar_contato(data)

            if tipo == "remover_contato":

                removido = (self.contacts.remove(data.get("chave") or data.get("nome"))
                            if self.contacts else False)

                return self.entregar_para_app({

                    "tipo": "evento" if removido else "erro",

                    "dados": "contato removido" if removido else "contato nao encontrado"

                })

            if tipo in ("contatos", "contacts"):

                return self.entregar_para_app({

                    "tipo": "contatos",

                    "dados": self.contacts.listar() if self.contacts else []

                })

            texto = data.get("dados") or data.get("data") or ""

            para = data.get("para") or data.get("to") or ""

        else:

            texto = str(data)

            if texto.strip().lower() in ("/convite", "/invite"):

                return self.criar_convite()

        texto = str(texto).strip()

        if not texto:

            return

        destino = self.contacts.find(para) if (self.contacts and para) else None

        if not destino:

            return self.entregar_para_app({

                "tipo": "erro",

                "dados": ("destinatario nao e um contato: %s" % para) if para

                         else "informe o destinatario: a mensagem vai cifrada para um contato"

            })

        pacote = self.messages.create_message(texto, destino)

        if not pacote:

            motivo = self.messages.validate_content(

                self.messages.sanitize(texto)

            ) or "mensagem recusada"

            return self.entregar_para_app({"tipo": "erro", "dados": motivo})

        radio = self.radio_padrao()

        # seção 8: o valor é decidido aqui, uma vez
        pontos = self.economy.message_points(

            pacote["packet"], radio["sf"], radio["bw"], radio["cr"]

        )

        self.registrar_corrida(pacote, pontos, radio)

        prioridade = self.economy.own_message_priority(

            self.neighbors.highest_points() if self.neighbors else 0

        )

        self.enfileirar(pacote, prioridade, radio, tipo="MESSAGE")

        self.stats["proprias"] += 1

        print("MENSAGEM PROPRIA para %s: %s | vale %.0f pontos | prioridade %.1f"
              % (self.contacts.nome(destino), pacote["hash"][:12], pontos, prioridade))


    def registrar_contato(self, data):
        """
        Registro manual ou por pedido de site/programa.
        Por enquanto aceito sem perguntar ao usuário.
        """

        if not self.contacts:

            return

        chave = str(data.get("chave") or data.get("key") or "").strip()

        if chave == self.identity.get_public_key():

            return self.entregar_para_app({

                "tipo": "erro", "dados": "essa e a carteira deste proprio no"

            })

        contato = self.contacts.add(

            chave,

            nome=data.get("nome") or data.get("name"),

            categoria=data.get("categoria") or data.get("category") or "pessoa",

            origem=data.get("origem") or "app"

        )

        if not contato:

            return self.entregar_para_app({"tipo": "erro", "dados": "chave publica invalida"})

        self.entregar_para_app({

            "tipo": "evento",

            "dados": "contato registrado: %s (%s)" % (contato["nome"], contato["categoria"])

        })


    def criar_convite(self):
        """
        [CHAVE PÚBLICA][ASSINATURA]<0>

        Entra na fila e tem prioridade, mas NÃO entra na lista corrida:
        convite não gera recompensa (seção 12).

        Também não entra no cache de memória. O cache existe para cortar
        retransmissão em loop, e convite não é retransmitido por ninguém.
        """

        if not self.messages:

            return

        convite = self.messages.create_invite()

        radio = self.radio_padrao()

        chave = self.identity.get_public_key()

        # O hash aqui serve só de identificador na fila. O convite não
        # entra no cache de memória: quem controla repetição de convite
        # é a lista de vizinhos, não o cache.
        prioridade = self.economy.own_message_priority(

            self.neighbors.highest_points() if self.neighbors else 0

        )

        self.enfileirar(

            {

                "packet": convite["packet"],

                "hash": self.cache.generate_hash(chave)

            },

            prioridade,

            radio,

            tipo="INVITE"

        )

        print("CONVITE ANUNCIADO:", self.identity.get_short_id())

    # =================================================
    # FILA DE RETRANSMISSÃO (seção 11)
    # =================================================

    def enfileirar(self, pacote, prioridade, radio, tipo="MESSAGE"):
        """
        Seção 21 - SF/BW/CR viajam junto com a mensagem, para a
        retransmissão sair com a mesma configuração com que ela chegou.
        """

        if not self.queue:

            return None

        return self.queue.add(

            pacote["packet"],

            pacote["hash"],

            prioridade,

            msg_type=tipo,

            sf=radio["sf"],

            bw=radio["bw"],

            cr=radio["cr"]

        )

    # =================================================
    # LISTA CORRIDA (seções 7 e 21)
    # =================================================

    def registrar_corrida(self, pacote, pontos, radio):
        """
        Seções 7 e 8 - SÓ mensagem própria. O valor é o tempo de antena
        dela, decidido aqui uma vez; depois só cai pela metade a cada
        posição, nas duas corridas.
        """

        if not self.race:

            return

        self.race.add_message(

            pacote["hash"], pontos, radio,

            pacote["hash_conteudo"], pacote["destinatario"]

        )


    def process_mac_event(self, event):

        if not event:

            return

        tipo = event.get("type")

        # -------------------------
        # TX FINALIZADO
        # -------------------------

        if tipo == "TX_DONE":

            # O valor da mensagem foi decidido quando ela entrou na
            # lista corrida e não muda mais. Aqui é só log: consulta o
            # que já está guardado em vez de medir a transmissão de
            # novo a cada envio.
            entrada = self.race.find(event.get("hash")) if self.race else None

            if entrada:

                print("TX FINALIZADO: %s | vale %.0f pontos | %s"
                      % (str(event.get("hash"))[:12], entrada["valor"],
                         "confirmada" if entrada["confirmada"]
                         else "aguardando confirmacao"))

            else:

                print("TX FINALIZADO:", str(event.get("hash"))[:12])

            self.depois_da_transmissao(event.get("hash"))

        # -------------------------
        # TX FALHOU
        # -------------------------

        elif tipo == "TX_FAILED":

            self.tx_falhou(event.get("hash"), event.get("motivo") or "")

        # -------------------------
        # RX FINALIZADO
        # -------------------------

        elif tipo == "RX_DONE":

            self.processar_pacote_recebido(event)

    def tx_falhou(self, msg_hash, motivo):
        """
        A transmissão não aconteceu. Há dois casos bem diferentes.

        TEMPORÁRIO (rádio não confirmou, canal, timeout): a mensagem
        fica na fila e será tentada de novo. É o certo: nada mudou
        sobre ela.

        DEFINITIVO (o rádio não consegue aplicar o SF/BW/CR dela): esta
        mensagem NUNCA vai poder ser transmitida por este nó. E como
        falha não desconta prioridade (seção 11 só desconta quando
        transmite), ela ficaria eternamente no topo da fila: o MAC
        escolhe, falha, escolhe de novo. O nó para de transmitir
        qualquer outra coisa.

        Medido: com o firmware antigo, uma única mensagem nessa
        situação derrubou a vazão do nó para ZERO pacote no ar.
        """

        print("TX FALHOU:", motivo)

        if not msg_hash:

            return

        if "SF/BW/CR" not in motivo:

            # temporário: continua na fila para nova tentativa
            return

        if self.queue:

            self.queue.remove(msg_hash)

        propria = False

        if self.race:

            entrada = self.race.find(msg_hash)

            propria = bool(entrada and entrada.get("own"))

        print("  mensagem %s removida da fila: o radio nao consegue"
              % msg_hash[:12])

        print("  transmitir com o SF/BW/CR dela (secao 21).")

        print("  Grave o firmware corrigido para casar os parametros.")

        if propria:

            self.entregar_para_app({

                "tipo": "erro",

                "dados": ("sua mensagem nao pode ser transmitida: o radio "
                          "nao consegue aplicar o SF/BW/CR dela (secao 21)")

            })


    def depois_da_transmissao(self, msg_hash):
        """
        Seção 11 - o MAC já chamou mark_transmitted, então a prioridade
        já caiu pela metade. A mensagem CONTINUA na fila: ela só sai
        por FIFO quando a fila lota (seções 11 e 23). Transmitir de
        novo é o que dá mais chance à mensagem; o que cai é a
        prioridade dela perante as outras.
        """

        if not (self.queue and msg_hash):

            return

        if PRIORIDADE_MINIMA <= 0:

            return

        for item in self.queue.get_all():

            if item["hash"] == msg_hash:

                if item["priority"] < PRIORIDADE_MINIMA:

                    self.queue.remove(msg_hash)

                return

    # =================================================
    # RECEPÇÃO (seções 13 a 21)
    # =================================================

    def processar_pacote_recebido(self, event):
        """
        A ordem da recepção:

         1  separar <0> e a assinatura do salto          seção 13
         2  hash do bloco (igual em todos os saltos)     seção 14
         3  convite?  -> vizinho desconhecido, PARA      seções 12 e 18
         4  a MINHA mensagem voltando?
                -> corrida da ida (retida até confirmar), PARA
         5  uma cópia da MINHA confirmação já reconhecida?
                -> corrida da volta, PARA
         6  já está no cache?  -> descarta               seção 14
         7  a assinatura do salto é de vizinho?          seção 15
         8  registra no cache
         9  tenta abrir com os contatos:
                mensagem para mim    -> app + confirmação
                confirmação para mim -> libera a ida, credita o contato,
                                        corrida da volta
                não abriu            -> sou relay           seções 16-21

        4 e 5 vêm ANTES do cache pelo mesmo motivo de sempre: a minha
        mensagem e a confirmação dela já estão no meu cache, e voltar é
        justamente o que precisa ser contado.
        """

        pacote = event.get("packet")

        if not pacote:

            return

        self.stats["recebidos"] += 1

        radio = event.get("radio") or self.radio_padrao()

        if not self.messages:

            return

        decodificado = self.messages.decode_packet(pacote)

        if not decodificado:

            return self.descartar("pacote malformado")

        conteudo = decodificado["content"]

        assinatura = decodificado["signature"]

        msg_hash = self.cache.generate_hash(conteudo)

        # ---- 3 ----
        if self.messages.is_invite(conteudo, assinatura):

            return self.tratar_convite(conteudo, assinatura, msg_hash)

        # ---- 4 ----
        if self.race and self.race.find(msg_hash):

            return self.retorno_da_ida(msg_hash, conteudo, assinatura, radio)

        # ---- 5 ----
        if self.race:

            entrada = self.race.find_confirmacao(msg_hash)

            if entrada:

                return self.retorno_da_volta(entrada, conteudo, assinatura, radio)

        # ---- 6 ----
        if self.cache.exists(msg_hash):

            return self.descartar("duplicada")

        # ---- 7 ----
        dono = self.messages.identify_signature_owner(conteudo, assinatura)

        if dono is None:

            return self.descartar("assinatura sem carteira conhecida")

        if dono == self.identity.get_public_key():

            return self.descartar("eco da minha propria transmissao")

        # ---- 8 ----
        self.cache.add(msg_hash)

        # ---- 9 ----
        aberto = None

        if self.contacts:

            aberto = self.messages.open_content(conteudo, self.contacts.chaves())

        if aberto and aberto["tipo"] == "CONFIRMATION":

            return self.chegada_da_confirmacao(aberto, msg_hash, dono, radio)

        if aberto and aberto["tipo"] == "MESSAGE":

            self.mensagem_para_mim(aberto, pacote, dono, radio, event)

            if not DESTINATARIO_RETRANSMITE:

                return

        return self.retransmitir(conteudo, msg_hash, pacote, dono, radio)


    def retransmitir(self, conteudo, msg_hash, pacote, dono, radio):
        """
        Não é para mim: sou relay. Troco a assinatura do salto
        (seção 16), calculo a prioridade (seções 17 e 20) e enfileiro
        com os mesmos SF/BW/CR (seção 21).

        NÃO entra na lista corrida: relay não paga ninguém.
        """

        tempo = self.economy.message_time_ms(

            pacote, radio["sf"], radio["bw"], radio["cr"]

        )

        tipo_vizinho = self.neighbors.get_type(dono) if self.neighbors else None

        if tipo_vizinho == "trusted":

            prioridade = self.economy.known_neighbor_priority(

                self.pontos_do_vizinho(dono), tempo,

                radio["sf"], radio["bw"], radio["cr"], packet=pacote

            )

        else:

            prioridade = self.economy.unknown_neighbor_priority(

                tempo, radio["sf"], radio["bw"], radio["cr"], packet=pacote

            )

        relay = self.messages.rebuild_relay_message(conteudo)

        self.enfileirar(

            {"packet": relay["packet"], "hash": msg_hash},

            prioridade, radio, tipo="MESSAGE"

        )

        self.stats["retransmitidos"] += 1

        print("RELAY %s de %s (%s) prioridade %.3f"
              % (msg_hash[:12], dono[:12], tipo_vizinho or "candidato", prioridade))


    def mensagem_para_mim(self, aberto, pacote, dono, radio, event):
        """
        Sou o destinatário. Entrego o texto e devolvo a confirmação:
        o hash do texto em claro, cifrado para o autor.

        A confirmação NÃO entra na minha lista corrida: quem paga quem a
        carregar é o autor, quando ela chegar nele.
        """

        autor = aberto["remetente"]

        self.stats["entregues"] += 1

        nome = self.contacts.nome(autor) if self.contacts else autor[:12]

        self.entregar_para_app({

            "tipo": "rx",

            "dados": aberto["texto"],

            "de": nome,

            "chave": autor[:12],

            "vizinho": dono[:12],

            "rssi": event.get("rssi"),

            "snr": event.get("snr"),

            "sf": radio["sf"], "bw": radio["bw"], "cr": radio["cr"]

        })

        confirmacao = self.messages.create_confirmation(autor, aberto["hash_conteudo"])

        if not confirmacao:

            print("nao consegui montar a confirmacao para", nome)

            return

        # a confirmação viaja com os mesmos SF/BW/CR da mensagem (seção 21)
        tempo_mensagem = self.economy.message_time_ms(

            pacote, radio["sf"], radio["bw"], radio["cr"]

        )

        tempo_confirmacao = self.economy.message_time_ms(

            confirmacao["packet"], radio["sf"], radio["bw"], radio["cr"]

        )

        prioridade = self.economy.confirmation_priority(

            self.contacts.get_points(autor) if self.contacts else 0,

            tempo_mensagem,

            tempo_confirmacao

        )

        self.enfileirar(confirmacao, prioridade, radio, tipo="CONFIRMATION")

        self.stats["confirmacoes_enviadas"] += 1

        print("ENTREGUE: mensagem de %s | confirmacao na fila, prioridade %.2f"
              % (nome, prioridade))


    def chegada_da_confirmacao(self, aberto, hash_bloco, dono, radio):
        """
        Primeira vez que vejo ESTA confirmação - sou o autor.

        Se for a primeira confirmação da mensagem: libero a corrida da
        ida retida e credito o destinatário em contatos. Em qualquer
        caso, quem a entregou ocupa uma posição na corrida da volta.
        """

        destinatario = aberto["remetente"]

        entrada = (self.race.find_por_conteudo(aberto["hash_conteudo"], destinatario)
                   if self.race else None)

        if not entrada:

            return self.descartar("confirmacao de mensagem fora da minha corrida")

        self.stats["confirmacoes_recebidas"] += 1

        resultado = self.race.confirmar(entrada["hash"], hash_bloco)

        if resultado["primeira"]:

            nome = self.contacts.nome(destinatario) if self.contacts else destinatario[:12]

            print("CONFIRMADA: %s recebeu %s" % (nome, entrada["hash"][:12]))

            for chave, pontos in resultado["liberar"]:

                self._pagar(chave, entrada["hash"], pontos, "ida liberada")

            if resultado["contato"] and self.contacts:

                chave_dest, valor = resultado["contato"]

                total = self.contacts.add_points(chave_dest, valor)

                if total is not None:

                    print("CONTATO: +%.0f pontos para %s | total %.0f"
                          % (valor, nome, total))

            self.entregar_para_app({

                "tipo": "entregue",

                "dados": "mensagem entregue a %s" % nome,

                "hash": entrada["hash"][:12]

            })

        return self._pagar_volta(entrada, dono, radio)


    def retorno_da_ida(self, msg_hash, conteudo, assinatura, radio):
        """
        Seções 10, 19 e 21 - a minha mensagem voltou retransmitida.
        A posição é ocupada agora; o pagamento espera a confirmação.
        """

        dono = self.messages.identify_signature_owner(conteudo, assinatura)

        if dono is None:

            return self.descartar("volta com assinatura desconhecida")

        if dono == self.identity.get_public_key():

            return self.descartar("eco da minha propria transmissao")

        r = self.race.retorno_ida(msg_hash, dono, radio)

        if not r["ok"]:

            print("SEM RECOMPENSA para %s: %s" % (dono[:12], r["motivo"]))

            return

        if r["retido"]:

            print("RETIDO: posicao %d da ida | %.0f pontos para %s aguardam a confirmacao"
                  % (r["posicao"], r["pontos"], dono[:12]))

            return

        self._pagar(dono, msg_hash, r["pontos"], "ida posicao %d" % r["posicao"])


    def retorno_da_volta(self, entrada, conteudo, assinatura, radio):
        """
        Outra cópia de uma confirmação que eu já reconheci.
        """

        dono = self.messages.identify_signature_owner(conteudo, assinatura)

        if dono is None:

            return self.descartar("confirmacao com assinatura desconhecida")

        if dono == self.identity.get_public_key():

            return self.descartar("eco da minha propria transmissao")

        return self._pagar_volta(entrada, dono, radio)


    def _pagar_volta(self, entrada, dono, radio):

        r = self.race.retorno_volta(entrada["hash"], dono, radio)

        if not r["ok"]:

            print("SEM RECOMPENSA (volta) para %s: %s" % (dono[:12], r["motivo"]))

            return

        self._pagar(dono, entrada["hash"], r["pontos"], "volta posicao %d" % r["posicao"])


    def _pagar(self, chave, msg_hash, pontos, origem):
        """
        Seção 19, na ordem certa: promove o candidato e DEPOIS credita.
        Uma posição retida é promovida só quando é paga - promover sem
        crédito deixaria o vizinho com zero, atrás de um desconhecido.
        """

        if not self.neighbors:

            return

        resultado = self.neighbors.register_relay_help(chave, msg_hash, pontos)

        if not resultado:

            print("sem carteira para pagar %.0f pontos (%s): %s"
                  % (pontos, origem, chave[:12]))

            return

        if resultado["promovido"]:

            print("PROMOVIDO A VIZINHO CONHECIDO:", chave[:12])

        self.stats["pontos_pagos"] += pontos

        print("RECOMPENSA (%s): +%.0f pontos para %s | total %.0f"
              % (origem, pontos, chave[:12], resultado["total"]))


    def tratar_convite(self, chave, assinatura, msg_hash):
        """
        Seções 12 e 18.

        Convite NÃO é retransmitido e NÃO entra no cache de memória.

        Ele é um anúncio de vizinhança direta: "esta é a minha carteira,
        estou ao alcance do seu rádio". Se fosse repassado adiante, todo
        nó da rede acabaria com a carteira de todo mundo em candidates,
        e a lista deixaria de significar "quem eu escuto".

        O controle de repetição não precisa do cache: a própria lista de
        vizinhos resolve. Chave já registrada -> nada a fazer.

        Como o convite não é repassado, também não existe a questão de
        reassinar (seção 16): a assinatura dele é a prova de posse da
        chave que viaja dentro, e ela fica intacta onde nasceu.
        """

        self.stats["convites_rx"] += 1

        # o message.py valida a assinatura contra a própria chave e
        # registra o candidato; aqui fica só a contagem e o log
        registrado = self.messages.register_invite(chave, assinatura)

        if registrado:

            print("NOVO VIZINHO DESCONHECIDO:", chave[:12])

            return

        # convite de carteira já conhecida, ou minha própria de volta:
        # nada a fazer, mas a conta de descartados precisa fechar com
        # o que realmente chegou no rádio
        self.stats["descartados"] += 1

    # =================================================
    # RECOMPENSA (seções 10, 19 e 21)
    # =================================================

    def descartar(self, motivo):

        self.stats["descartados"] += 1

        print("  descartado:", motivo)

        return None

    def entregar_para_app(self, dados):

        if not servidor_app:

            return

        try:

            servidor_app.enviar_para_aplicacao(dados)

        except Exception as erro:

            print("falha ao entregar para a aplicacao:", erro)

    # =================================================
    # MANUTENÇÃO
    # =================================================

    def manutencao(self):

        agora = time.time()

        if (CONVITE_MODO == "periodico"
                and INTERVALO_CONVITE
                and agora - self.ultimo_convite > INTERVALO_CONVITE):

            self.ultimo_convite = agora

            self.criar_convite()

        if agora - self.ultimo_salvar > INTERVALO_SALVAR:

            self.ultimo_salvar = agora

            self.cache.flush()

            self.salvar_vizinhos()

            if self.race:

                self.race.save()

        if agora - self.ultima_manutencao > INTERVALO_MANUTENCAO:

            self.ultima_manutencao = agora

            self.imprimir_estado()

    def resumo(self):
        """
        Estado do nó em uma olhada. Alimenta o botão status da página
        e a rota /status do servidor.
        """

        dados = {

            "carteira": self.identity.get_short_id(),

            "fila": self.queue.size() if self.queue else 0,

            "corrida": self.race.size() if self.race else 0,

            "cache": self.cache.size(),

            "conhecidos": 0,

            "candidatos": 0,

            "maior_pontuacao": 0

        }

        if self.neighbors:

            dados.update({

                "conhecidos": len(self.neighbors.get_trusted()),

                "candidatos": len(self.neighbors.get_candidates()),

                "maior_pontuacao": round(self.neighbors.highest_points(), 1)

            })

        if self.messages:

            # a página usa isto no contador; sem ele ela fica com o
            # valor fixo dela, que pode divergir do nó
            dados["limite_texto"] = self.messages.max_content_size()

        dados.update({

            "convites_rx": self.stats["convites_rx"],

            "recebidos": self.stats["recebidos"],

            "retransmitidos": self.stats["retransmitidos"],

            "proprias": self.stats["proprias"],

            "descartados": self.stats["descartados"],

            "pontos_pagos": round(self.stats["pontos_pagos"], 1),

            "entregues": self.stats["entregues"],

            "confirmacoes_enviadas": self.stats["confirmacoes_enviadas"],

            "confirmacoes_recebidas": self.stats["confirmacoes_recebidas"]

        })

        # a chave inteira: é o que outro nó precisa para me registrar
        dados["chave_publica"] = self.identity.get_public_key()

        dados["contatos"] = self.contacts.listar() if self.contacts else []

        if self.race:

            dados["corrida_detalhe"] = self.race.resumo()

        return dados


    def imprimir_estado(self):

        conhecidos = len(self.neighbors.get_trusted()) if self.neighbors else 0

        candidatos = len(self.neighbors.get_candidates()) if self.neighbors else 0

        print("[ESTADO] fila %d | corrida %d | conhecidos %d | candidatos %d"
              " | rx %d | retx %d | pagos %.0f"
              % (self.queue.size() if self.queue else 0,
                 self.race.size() if self.race else 0,
                 len(self.neighbors.get_trusted()),
                 len(self.neighbors.get_candidates()),
                 self.stats["recebidos"],
                 self.stats["retransmitidos"],
                 self.stats["pontos_pagos"]))

    def encerrar(self, *args):

        if not self.rodando:

            return

        self.rodando = False

        print("\nencerrando GhostRelay...")

        try:

            self.cache.flush()

            self.salvar_vizinhos()

            if self.race:

                self.race.save()

            if self.contacts:

                self.contacts.save()

            print("estado salvo")

        except Exception as erro:

            print("falha ao salvar:", erro)

        sys.exit(0)

    # =================================================
    # LOOP PRINCIPAL
    # =================================================

    def run(self):

        signal.signal(signal.SIGINT, self.encerrar)

        signal.signal(signal.SIGTERM, self.encerrar)

        # ---- servidor da aplicação (seção 22) -----------------------
        if servidor_app:

            # o servidor pergunta o estado do nó por aqui
            try:

                servidor_app.registrar_status(self.resumo)

            except AttributeError:

                pass

            threading.Thread(

                target=self.rodar_servidor,

                daemon=True,

                name="servidor"

            ).start()

            time.sleep(0.5)

        else:

            print("AVISO: server.py indisponivel - sem WebSocket")

        # ---- MAC ----------------------------------------------------
        if self.mac:

            threading.Thread(

                target=self.mac.iniciar,

                daemon=True,

                name="mac"

            ).start()

        else:

            print("AVISO: sem radio - o no nao transmite nem recebe")

        # o nó se anuncia ao subir só no modo periódico
        if CONVITE_MODO == "periodico":

            time.sleep(1)

            self.criar_convite()

            self.ultimo_convite = time.time()

        else:

            print("convite em modo manual: mande /convite pela aplicacao")

        while self.rodando:

            # ---- mensagens da aplicação -----------------------------
            if servidor_app:

                try:

                    app_message = servidor_app.obter_mensagem_tx(timeout=0.05)

                    if app_message:

                        self.process_application_message(app_message)

                except Exception:

                    pass

            else:

                time.sleep(0.05)

            # ---- eventos do MAC -------------------------------------
            #
            # Drena tudo que está pendente. Antes o laço parava até 1
            # segundo esperando UM evento, e nesse tempo nada mais
            # andava no nó.
            if mac_events:

                while True:

                    try:

                        evento = mac_events.get_nowait()

                    except Exception:

                        break

                    try:

                        self.process_mac_event(evento)

                    except Exception as erro:

                        print("erro ao processar evento:", erro)

            self.manutencao()

    def rodar_servidor(self):

        try:

            import asyncio

            asyncio.run(servidor_app.main())

        except Exception as erro:

            print("servidor caiu:", erro)


# =====================================================
# START
# =====================================================


if __name__ == "__main__":

    node = GhostRelayNode()

    node.run()
