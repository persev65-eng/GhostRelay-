#!/usr/bin/env python3

"""
GhostRelay - Message Protocol

Responsabilidades:

- Criar mensagens próprias
- Criar convites
- Separar assinatura
- Validar assinatura
- Controlar retransmissão fantasma

Formato mensagem:

[MENSAGEM][ASSINATURA]<0>

Formato convite:

[CHAVE_PUBLICA][ASSINATURA]<0>


IMPORTANTE:

- Mensagens comuns entram no cache.
- Convites NÃO entram no cache.
- Hash nunca inclui assinatura nem <0>.
- Retransmissão substitui assinatura antiga.


ESTE MÓDULO É O DONO DO FORMATO DO PACOTE
-----------------------------------------
Ele monta, separa e valida pacote. Ele NÃO decide o que fazer com a
mensagem: consultar cache, consultar lista corrida, calcular prioridade
e enfileirar são decisões de fluxo, e quem toma é o main.py.

Essa separação não é estética. A ordem entre consultar a lista corrida e
consultar o cache é o que faz a seção 10 existir (a mensagem própria já
está no cache desde que foi criada). Com o message.py decidindo
descarte por conta própria, essa ordem ficava fora do alcance de quem
precisa dela.


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) identify_signature_owner() NUNCA ACHAVA NINGUÉM.

   Ele varria self.known_keys, um dicionário que nada populava:
   register_public_key() não era chamado em lugar nenhum. Sempre
   devolvia None, e pela seção 15 toda mensagem seria descartada.
   Agora a busca usa a lista de vizinhos (trusted + candidates), que é
   o que a seção 15 manda consultar.

2) process_received() MATAVA A RECOMPENSA.

   Ele consultava o cache e descartava duplicata antes de qualquer
   outra coisa. Como a mensagem própria entra no cache na hora de ser
   criada (seção 5), ela seria descartada ao voltar e a seção 10 nunca
   pagaria ninguém. Ele agora só descreve o pacote, sem mexer no cache
   e sem decidir descarte.

3) NÃO HAVIA COMO SABER SE UM PACOTE ERA CONVITE.

   O documento não põe campo de tipo no pacote. is_invite() responde a
   pergunta da seção 18: o conteúdo tem o tamanho de uma chave pública
   e a assinatura fecha com essa mesma chave?

4) NÃO HAVIA LIMITE DE TAMANHO.

   Um pacote LoRa tem 255 bytes. Com 88 de assinatura e 3 do marcador,
   sobram 164 caracteres para o texto. Acima disso o rádio recusava a
   transmissão e a mensagem sumia sem explicação.

5) CONTEÚDO PODIA CONTER \\n OU O PRÓPRIO <0>.

   Quebra de linha corta o pacote na serial; um <0> no meio do texto
   engana quem estiver escutando até achar o fim da transmissão
   (seção 13).
"""


END_MARKER = "<0>"


# Limite de um pacote LoRa
MAX_PACOTE = 255


class GhostMessage:


    def __init__(
        self,
        identity,
        cache,
        neighbors=None
    ):

        self.identity = identity
        self.cache = cache
        self.neighbors = neighbors


        # Controle de carteiras conhecidas.
        # A assinatura recebida precisa ser
        # associada a uma chave pública.
        #
        # Registro manual, para carteiras que não vieram por convite.
        # A fonte principal é o neighbors.
        self.known_keys = {}


    # =================================================
    # LIMITES DO RÁDIO
    # =================================================


    def signature_size(self):

        return self.identity.signature_size()


    def max_content_size(self):
        """
        Quanto texto cabe em uma transmissão:

            255 (pacote LoRa)
            -88 (assinatura Ed25519 em base64)
             -3 (marcador <0>)
            ----
            164 caracteres
        """

        return MAX_PACOTE - self.signature_size() - len(END_MARKER)


    def fits_in_packet(self, packet):

        return len(str(packet).encode("utf-8")) <= MAX_PACOTE


    def sanitize(self, content):
        """
        Tira o que quebraria o transporte.

        \\r e \\n cortam a linha da serial ao meio: o ESP32 leria meia
        mensagem como se fosse inteira.
        """

        return (
            str(content)
            .replace("\r", " ")
            .replace("\n", " ")
        )


    def validate_content(self, content):
        """
        Devolve None se o conteúdo pode virar mensagem,
        ou o motivo da recusa.
        """

        if content is None:

            return "conteudo vazio"

        texto = str(content)

        if not texto.strip():

            return "conteudo vazio"

        if END_MARKER in texto:

            # seção 13: o receptor escuta até encontrar o <0>. Um <0> no
            # meio do texto faria ele considerar a mensagem terminada
            # antes da hora.
            return "conteudo contem o marcador de fim %s" % END_MARKER

        tamanho = len(texto.encode("utf-8"))

        if tamanho > self.max_content_size():

            return ("conteudo de %d bytes; o maximo por pacote e %d"
                    % (tamanho, self.max_content_size()))

        return None


    # =================================================
    # MENSAGEM PRÓPRIA
    # =================================================


    def create_message(self, content):
        """
        Seção 5:

        criar -> assinar -> marcador <0> -> hash -> cache

        O hash é calculado só sobre a mensagem, sem assinatura e sem o
        <0>: é isso que faz ele sobreviver à troca de assinatura da
        seção 16 e ser o mesmo em todos os nós.

        Devolve None se o conteúdo não pode ser transmitido.
        """

        content = self.sanitize(content)

        motivo = self.validate_content(content)

        if motivo:

            print("[MESSAGE] mensagem recusada:", motivo)

            return None

        signature = self.identity.sign(
            content
        )


        packet = (
            content
            +
            signature
            +
            END_MARKER
        )


        msg_hash = self.cache.generate_hash(
            content
        )


        # Mensagem própria entra no cache
        self.cache.add(
            msg_hash
        )


        return {

            "type": "MESSAGE",

            "packet": packet,

            "hash": msg_hash,

            "content": content,

            "signature": signature,

            "own": True

        }



    # =================================================
    # CONVITE DE CARTEIRA
    # =================================================


    def create_invite(self):
        """
        Seção 12:

        [CHAVE_PUBLICA][ASSINATURA]<0>

        A assinatura é feita sobre a própria chave pública: é ela que
        prova posse da carteira anunciada (seção 18, item 1).

        Convite NÃO entra no cache de memória: o cache existe para
        cortar retransmissão em loop, e convite não é retransmitido por
        ninguém. Quem controla repetição de convite é a lista de
        vizinhos.
        """

        public_key = (
            self.identity.get_public_key()
        )


        signature = self.identity.sign(
            public_key
        )


        packet = (
            public_key
            +
            signature
            +
            END_MARKER
        )


        return {

            "type": "INVITE",

            "packet": packet,

            "public_key": public_key,

            "signature": signature

        }



    # =================================================
    # SEPARAR PACOTE
    # =================================================


    def decode_packet(
        self,
        packet
    ):
        """
        Seção 13:

        1 - remove o <0>
        2 - separa a assinatura contando de trás para frente
            (o tamanho dela é fixo)
        3 - o que sobra é a mensagem
        """

        if packet is None:

            return None

        if isinstance(packet, bytes):

            packet = packet.decode("utf-8", "ignore")

        packet = str(packet)


        if not packet.endswith(
            END_MARKER
        ):

            return None



        packet = packet[
            :-len(END_MARKER)
        ]


        signature_size = (
            self.identity.signature_size()
        )


        if len(packet) <= signature_size:

            return None



        signature = packet[
            -signature_size:
        ]


        content = packet[
            :-signature_size
        ]



        return {

            "content": content,

            "signature": signature

        }


    # =================================================
    # É CONVITE OU MENSAGEM?
    # =================================================


    def is_invite(self, content, signature):
        """
        Seção 18, item 1 - "a assinatura corresponde à chave pública?"

        O documento não põe campo de tipo dentro do pacote, e não
        precisa: o convite se identifica sozinho. Só é convite se o
        conteúdo tiver exatamente o tamanho de uma chave pública E a
        assinatura fechar com esse mesmo conteúdo tratado como chave.

        Um texto qualquer do tamanho de uma chave não passa nesse teste.
        """

        return self.identity.looks_like_invite(content, signature)


    # =================================================
    # PROCESSAR MENSAGEM RECEBIDA
    # =================================================


    def process_received(
        self,
        packet
    ):
        """
        Descreve um pacote recebido. NÃO mexe no cache e NÃO decide
        descarte: essas decisões são do main.py, porque dependem da
        lista corrida (seções 10 e 14).

        Devolve:

            {
              "type": "MESSAGE" ou "INVITE",
              "hash": ...,
              "content": ...,
              "signature": ...,
              "owner": carteira que assinou, ou None
            }
        """

        decoded = self.decode_packet(
            packet
        )


        if not decoded:

            return None



        content = decoded["content"]

        signature = decoded["signature"]



        msg_hash = self.cache.generate_hash(
            content
        )


        if self.is_invite(content, signature):

            return {

                "type": "INVITE",

                "hash": msg_hash,

                "content": content,

                "signature": signature,

                "owner": content

            }


        owner = self.identify_signature_owner(
            content,
            signature
        )


        return {

            "type": "MESSAGE",

            "hash": msg_hash,

            "content": content,

            "signature": signature,

            "owner": owner

        }



    # =================================================
    # PROCESSAR CONVITE RECEBIDO
    # =================================================


    def register_invite(
        self,
        public_key,
        signature
    ):
        """
        Seções 12 e 18 - convite já separado do pacote.

        1 - a assinatura corresponde à chave pública?
        2 - essa chave já existe em alguma lista?

        Já existe -> nada a fazer.
        Não existe -> entra em candidates (vizinhos desconhecidos).

        Convite não é retransmitido e não entra no cache: quem controla
        repetição dele é a própria lista de vizinhos.
        """

        # A assinatura do convite prova
        # que a chave pertence ao dono
        if not self.identity.verify(
            public_key,
            public_key,
            signature
        ):

            return None


        if public_key == self.identity.get_public_key():

            return None


        if self.neighbors:


            if self.neighbors.exists(
                public_key
            ):

                return None



            self.neighbors.add_candidate(
                public_key
            )


        return {

            "type": "INVITE",

            "public_key": public_key

        }


    def process_invite(
        self,
        packet
    ):
        """
        Mesma coisa, a partir do pacote cru.
        """

        decoded = self.decode_packet(
            packet
        )


        if not decoded:

            return None


        return self.register_invite(

            decoded["content"],

            decoded["signature"]

        )



    # =================================================
    # REGISTRO DE CARTEIRAS CONHECIDAS
    # =================================================


    def register_public_key(
        self,
        public_key
    ):

        """
        Registra uma carteira conhecida
        para futura identificação de assinatura.

        Uso manual: a fonte normal de carteiras é o neighbors,
        alimentado pelos convites.
        """


        if public_key:

            self.known_keys[public_key] = True


    def known_wallets(self):
        """
        Seção 15 - contra quais carteiras a assinatura é testada,
        na ordem: vizinhos conhecidos, candidatos, registro manual.
        """

        chaves = []

        if self.neighbors:

            chaves.extend(self.neighbors.get_trusted())

            chaves.extend(self.neighbors.get_candidates())

        for chave in self.known_keys:

            if chave not in chaves:

                chaves.append(chave)

        return chaves



    def identify_signature_owner(
        self,
        content,
        signature
    ):

        """
        Descobre qual carteira gerou
        a assinatura.

        Ordem:

        trusted
        candidate
        desconhecido

        Antes isto varria self.known_keys, que ninguém preenchia, e
        devolvia None sempre. Agora a fonte é a lista de vizinhos.
        """

        return self.identity.find_signer(

            content,

            signature,

            self.known_wallets()

        )



    def process_relay_received(
        self,
        packet
    ):

        """
        Fluxo completo de retransmissão:

        recebe:

        [MENSAGEM][ASS_A]<0>


        remove ASS_A


        assina novamente:


        [MENSAGEM][ASS_B]<0>
        """


        decoded = self.decode_packet(
            packet
        )


        if not decoded:

            return None



        content = decoded["content"]

        old_signature = decoded["signature"]



        # convite não é retransmitido
        if self.is_invite(content, old_signature):

            return None



        owner = self.identify_signature_owner(
            content,
            old_signature
        )


        if owner is None:

            return None



        relay = self.rebuild_relay_message(
            content
        )


        return {

            "type": "RELAY",

            "original_owner": owner,

            "content": content,

            "hash": self.cache.generate_hash(content),

            "packet": relay["packet"],

            "signature": relay["signature"]

        }


    # =================================================
    # RETRANSMISSÃO
    # =================================================


    def rebuild_relay_message(
        self,
        content
    ):

        """
        Seção 16 - remove a assinatura anterior e põe a minha.
        Nunca acumula assinaturas.

        O conteúdo não muda, então o hash continua o mesmo e o cache de
        todo mundo reconhece a mensagem. A origem continua desconhecida:
        quem recebe só sabe quem transmitiu daquela vez.
        """


        signature = self.identity.sign(
            content
        )


        packet = (
            content
            +
            signature
            +
            END_MARKER
        )


        return {

            "packet": packet,

            "signature": signature

        }



    # =================================================
    # VALIDAR ASSINATURA
    # =================================================


    def verify_message(
        self,
        public_key,
        content,
        signature
    ):

        return self.identity.verify(
            public_key,
            content,
            signature
        )
