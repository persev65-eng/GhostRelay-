#!/usr/bin/env python3

"""
FORMATO NOVO (confirmação de entrega)
-------------------------------------
Mensagem e confirmação usam o mesmo formato de fora de sempre:

    [BLOCO CIFRADO EM BASE64][ASSINATURA DO SALTO]<0>

O bloco é uma caixa autenticada (crypto_box do NaCl) entre o autor e o
destinatário: só o destinatário abre, e abrir já prova quem criou - a
assinatura do autor vai fundida na cifragem. Dentro dele:

    "M" + texto          mensagem         (até 82 bytes de texto)
    "C" + hash do texto  confirmação      (32 bytes)

Os relays não leem nada: veem só o bloco, o reassinam no salto e o
passam adiante. O hash do bloco é igual em todos os saltos, e é o que
o cache e o reconhecimento de retorno usam.

Convite não muda: [CHAVE PÚBLICA][ASSINATURA]<0>, em claro.

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


import base64
import hashlib


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
        Quanto TEXTO cabe numa mensagem cifrada:

            255  pacote LoRa
            -88  assinatura do salto (base64)
             -3  marcador <0>
            ----
            164  caracteres de base64 para o bloco cifrado
                 = 123 bytes de bloco
            -40  cifragem (24 nonce + 16 autenticação)
             -1  tipo (mensagem ou confirmação)
            ----
             82  bytes de texto

        A "assinatura do autor" não aparece na conta porque vai fundida
        na cifragem autenticada: abrir o bloco já prova quem o criou.
        """

        base64_livre = MAX_PACOTE - self.signature_size() - len(END_MARKER)

        bloco = (base64_livre // 4) * 3

        return bloco - self.identity.BOX_SOBRECARGA - 1


    def _max_content_size_claro(self):
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

        # O <0> no meio do texto deixou de ser problema: o texto vai
        # cifrado e em base64, que nunca contém "<" nem ">".

        tamanho = len(texto.encode("utf-8"))

        if tamanho > self.max_content_size():

            return ("conteudo de %d bytes; o maximo por pacote e %d"
                    % (tamanho, self.max_content_size()))

        return None


    # =================================================
    # MENSAGEM PRÓPRIA
    # =================================================


    # tipos, no primeiro byte do texto cifrado (invisível para os relays)
    TIPO_MENSAGEM = b"M"

    TIPO_CONFIRMACAO = b"C"


    def _montar(self, texto_claro, destinatario, tipo_pacote):
        """
        [BLOCO CIFRADO EM BASE64][ASSINATURA DO SALTO]<0>

        O formato de fora é o mesmo de sempre, e por isso o resto do
        protocolo não muda: o cache, a troca de assinatura a cada salto
        (seção 16) e a identificação do vizinho (seção 15) tratam o
        bloco como um conteúdo qualquer. O hash do bloco é igual em
        todos os saltos.
        """

        bloco = self.identity.cifrar_para(destinatario, texto_claro)

        if bloco is None:

            print("[MESSAGE] nao consegui cifrar para", str(destinatario)[:12])

            return None

        conteudo = base64.b64encode(bloco).decode("ascii")

        assinatura = self.identity.sign(conteudo)

        pacote = conteudo + assinatura + END_MARKER

        if not self.fits_in_packet(pacote):

            print("[MESSAGE] pacote passou de %d bytes" % MAX_PACOTE)

            return None

        msg_hash = self.cache.generate_hash(conteudo)

        # o próprio nó não pode tratar o pacote dele como novo quando
        # ele voltar pelo ar
        self.cache.add(msg_hash)

        return {"type": tipo_pacote, "packet": pacote, "hash": msg_hash,
                "content": conteudo, "signature": assinatura,
                "destinatario": destinatario, "own": True}


    def create_message(self, content, destinatario=None):
        """
        Seção 5, com cifragem:

            texto -> cifrar para o destinatário (autor autenticado)
                  -> base64 -> assinatura do salto -> <0> -> hash -> cache

        Devolve None se não der para transmitir.
        """

        if not destinatario:

            print("[MESSAGE] mensagem sem destinatario")

            return None

        content = self.sanitize(content)

        motivo = self.validate_content(content)

        if motivo:

            print("[MESSAGE] mensagem recusada:", motivo)

            return None

        claro = self.TIPO_MENSAGEM + content.encode("utf-8")

        pacote = self._montar(claro, destinatario, "MESSAGE")

        if pacote:

            # o que a confirmação vai carregar: só autor e destinatário
            # conhecem o texto, então só eles calculam este hash
            pacote["hash_conteudo"] = hashlib.sha256(claro).hexdigest()

            pacote["texto"] = content

        return pacote


    def create_confirmation(self, autor, hash_conteudo):
        """
        Confirmação de entrega: o hash do texto em claro, cifrado para o
        autor. Só o destinatário verdadeiro consegue fazê-la - precisou
        abrir a mensagem para conhecer o hash, e a cifragem autenticada
        prova que foi ele.
        """

        try:

            bruto = bytes.fromhex(hash_conteudo)

        except (TypeError, ValueError):

            return None

        return self._montar(self.TIPO_CONFIRMACAO + bruto, autor, "CONFIRMATION")


    def open_content(self, content, chaves_contatos):
        """
        Tenta abrir o conteúdo com cada contato.

        None se não abriu: não é para mim, sigo como relay. Mensagem
        para mim de quem NÃO é contato também não abre, e segue adiante
        como tráfego alheio - não há como distinguir as duas coisas, e
        isso é bom para o anonimato.

        Se abriu:
            {"tipo": "MESSAGE", "remetente", "texto", "hash_conteudo"}
            {"tipo": "CONFIRMATION", "remetente", "hash_conteudo"}
        """

        if not chaves_contatos:

            return None

        try:

            bloco = base64.b64decode(content, validate=True)

        except Exception:

            return None

        if len(bloco) <= self.identity.BOX_SOBRECARGA:

            return None

        remetente, claro = self.identity.abrir_de_algum(chaves_contatos, bloco)

        if not claro:

            return None

        tipo = claro[:1]

        if tipo == self.TIPO_MENSAGEM:

            return {"tipo": "MESSAGE", "remetente": remetente,
                    "texto": claro[1:].decode("utf-8", "replace"),
                    "hash_conteudo": hashlib.sha256(claro).hexdigest()}

        if tipo == self.TIPO_CONFIRMACAO and len(claro) == 33:

            return {"tipo": "CONFIRMATION", "remetente": remetente,
                    "hash_conteudo": claro[1:].hex()}

        return None


    def create_message_claro(self, content):
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
