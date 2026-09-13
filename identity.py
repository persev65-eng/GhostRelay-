"""
GhostRelay - Identity Module

Responsabilidade:

- Gerenciamento da carteira do nó
- Chaves Ed25519
- Assinatura digital
- Verificação de assinatura
- Convites de carteira

Não controla:
- mensagens
- cache
- economia
- vizinhos


SEÇÕES DO PROTOCOLO IMPLEMENTADAS AQUI
--------------------------------------
  2   carteira: chave privada fica no dispositivo, pública é compartilhada
 12   convite: [CHAVE PÚBLICA][ASSINATURA]<0>
 13   assinatura de TAMANHO FIXO, separável contando de trás para frente
 15   descobrir a qual carteira uma assinatura pertence
 16   assinar de novo a cada retransmissão
 18   convite válido = assinatura corresponde à chave pública


TAMANHOS FIXOS (base64)
-----------------------
    chave pública  32 bytes ->  44 caracteres
    assinatura     64 bytes ->  88 caracteres

Base64 usa só A-Z a-z 0-9 + / = , então nunca produz '<', '>' nem quebra
de linha: o marcador <0> continua reconhecível e a serial não quebra.
Como é ASCII puro, 88 caracteres são exatamente 88 bytes — contar de trás
para frente dá o mesmo resultado em str ou em bytes.


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) A CARTEIRA ERA REGENERADA A CADA BOOT.

   save_wallet() gravava no storage e dava return ANTES de criar o
   private.key. Mas load_or_create() decidia olhando só se o private.key
   existia. Como esse arquivo nunca era criado, todo boot caía em
   create_wallet() e sobrescrevia a identidade no storage.

   O nó perdia a chave privada, perdia todos os pontos que os vizinhos
   tinham acumulado para ele e voltava à rede como estranho — tendo que
   mandar convite e ser promovido de novo (seções 18 e 19), toda vez.

   Agora a decisão de carregar usa a MESMA fonte em que se grava, e há
   migração do arquivo antigo para o storage.

2) FALTAVA signature_size().

   O message.py chama self.identity.signature_size() para separar a
   assinatura contando de trás para frente (seção 13). O método não
   existia: era AttributeError em TODO pacote recebido.

3) verify() só capturava BadSignatureError.

   Chave malformada, base64 inválido ou tamanho errado levantam outras
   exceções (ValueError, TypeError, CryptoError). Como a seção 15 manda
   testar a assinatura contra várias carteiras em sequência, uma chave
   ruim na lista derrubava a identificação inteira. Verificação agora
   nunca levanta exceção: ou é True, ou é False.

4) A chave privada era gravada com permissão padrão, legível por
   qualquer usuário da máquina. Agora é 0600.
"""


import base64
import os
import stat

try:

    from nacl.signing import SigningKey, VerifyKey

except ImportError:

    raise ImportError(
        "GhostRelay precisa da biblioteca PyNaCl para as chaves Ed25519.\n"
        "Instale com:  pip install pynacl"
    )


try:

    from storage import Storage

except Exception:

    Storage = None


# =====================================================
# CONFIGURAÇÃO
# =====================================================


PRIVATE_KEY_FILE = "private.key"


# Marcador de fim de transmissão (seção 4)
END_MARKER = "<0>"


# Tamanhos fixos, já em base64 (seção 13)
SIGNATURE_SIZE = 88

PUBLIC_KEY_SIZE = 44


# Tamanhos crus, antes do base64
RAW_SEED_SIZE = 32

RAW_SIGNATURE_SIZE = 64

RAW_PUBLIC_KEY_SIZE = 32


# =====================================================
# CLASSE IDENTIDADE
# =====================================================


class GhostIdentity:


    def __init__(
        self,
        storage=None,
        key_file=PRIVATE_KEY_FILE
    ):
        """
        storage:
            instância de Storage. Se não vier, tenta criar uma.

        key_file:
            arquivo da chave privada. Trocar esse nome permite rodar
            dois nós na mesma máquina para teste, cada um com a sua
            carteira.

            Atenção: o storage tem um único espaço de identidade por
            pasta. Quando key_file é diferente do padrão, o storage
            automático NÃO é usado — senão os dois nós carregariam a
            mesma carteira e a rede viraria um nó falando sozinho.
        """

        self.private_key = None

        self.public_key = None

        self.key_file = key_file

        self.storage = storage


        # storage automático só no modo de nó único
        if self.storage is None and Storage:

            if key_file == PRIVATE_KEY_FILE:

                try:

                    self.storage = Storage()

                except Exception:

                    self.storage = None


        self.load_or_create()


    def __repr__(self):

        return "<GhostIdentity %s>" % self.get_short_id()


    # =================================================
    # CARREGAR OU CRIAR CARTEIRA
    # =================================================

    def load_or_create(self):
        """
        Ordem de procura:

        1 - storage.py         (fonte preferida)
        2 - arquivo legado     (migra para o storage)
        3 - cria uma carteira nova

        A regra importante: carregar e salvar usam a MESMA fonte.
        Era essa assimetria que fazia o nó trocar de identidade
        a cada reinício.
        """

        if self._load_from_storage():

            return

        if self._load_from_file():

            # migra a carteira antiga para o storage
            self.save_wallet()

            return

        self.create_wallet()


    def _load_from_storage(self):

        if not self.storage:

            return False

        try:

            saved = self.storage.load_identity()

        except Exception:

            return False

        # o storage devolve {} quando não há nada gravado
        if not saved or not isinstance(saved, str):

            return False

        return self._aplicar_semente(saved, origem="storage")


    def _load_from_file(self):

        if not os.path.exists(self.key_file):

            return False

        try:

            with open(self.key_file, "rb") as arquivo:

                conteudo = arquivo.read().strip()

        except OSError:

            return False

        if not conteudo:

            return False

        return self._aplicar_semente(

            conteudo.decode("ascii", "ignore"),

            origem=self.key_file

        )


    def _aplicar_semente(self, encoded, origem):
        """
        Converte a chave gravada em carteira utilizável.

        Chave corrompida não pode virar carteira nova em silêncio:
        isso seria perder a identidade sem ninguém perceber. O arquivo
        ruim é preservado com outro nome para análise.
        """

        try:

            raw = base64.b64decode(encoded)

        except Exception:

            raw = b""

        if len(raw) != RAW_SEED_SIZE:

            print(
                "[IDENTITY] chave invalida em %s (%d bytes, esperado %d)"
                % (origem, len(raw), RAW_SEED_SIZE)
            )

            self._preservar_chave_ruim()

            return False

        try:

            self.private_key = SigningKey(raw)

            self.public_key = self.private_key.verify_key

        except Exception as erro:

            print("[IDENTITY] falha ao abrir a carteira:", erro)

            self._preservar_chave_ruim()

            return False

        return True


    def _preservar_chave_ruim(self):

        if not os.path.exists(self.key_file):

            return

        destino = self.key_file + ".invalido"

        try:

            os.replace(self.key_file, destino)

            print("[IDENTITY] chave ilegivel movida para", destino)

        except OSError:

            pass


    # =================================================
    # CRIAR NOVA CARTEIRA
    # =================================================

    def create_wallet(self):

        """
        Cria uma nova identidade Ed25519
        """

        signing_key = SigningKey.generate()


        self.private_key = signing_key


        self.public_key = (
            signing_key.verify_key
        )


        self.save_wallet()

        print("[IDENTITY] nova carteira criada:", self.get_short_id())


    # =================================================
    # SALVAR CHAVE PRIVADA
    # =================================================

    def save_wallet(self):

        """
        Salva somente a chave privada.

        A chave pública pode ser
        regenerada através dela.

        Grava no storage quando ele existe; sem storage, grava no
        arquivo legado. Se o storage falhar, cai para o arquivo em vez
        de perder a chave.
        """

        raw = bytes(
            self.private_key
        )


        encoded = base64.b64encode(
            raw
        )


        # Prefer storage.py

        if self.storage:


            try:

                self.storage.save_identity(

                    encoded.decode()

                )


                return True


            except Exception as erro:

                print("[IDENTITY] storage falhou:", erro)



        # Fallback legacy file

        try:

            with open(self.key_file, "wb") as arquivo:

                arquivo.write(encoded)

            # a chave privada nunca deve ficar legível para outros
            # usuários da máquina (seção 2)
            os.chmod(self.key_file, stat.S_IRUSR | stat.S_IWUSR)

            return True

        except OSError as erro:

            print("[IDENTITY] nao consegui gravar a chave:", erro)

            return False


    # =================================================
    # CARREGAR CARTEIRA
    # =================================================

    def load_wallet(self):
        """
        Recarrega a carteira do disco.
        Mantido para compatibilidade com quem já chamava este método.
        """

        if self._load_from_storage():

            return True

        return self._load_from_file()


    # =================================================
    # CHAVE PÚBLICA
    # =================================================

    def get_public_key(self):

        """
        Retorna chave pública
        para compartilhamento.
        """

        return base64.b64encode(
            bytes(
                self.public_key
            )
        ).decode()


    def get_short_id(self):
        """
        Identificação curta para log. Não use em protocolo:
        a carteira completa é que identifica o nó.
        """

        return self.get_public_key()[:12]


    # =================================================
    # TAMANHOS FIXOS (SEÇÃO 13)
    # =================================================

    @staticmethod
    def signature_size():
        """
        Tamanho da assinatura em caracteres.

        É o que permite ao receptor separar a assinatura contando de
        trás para frente, sem nenhum delimitador entre mensagem e
        assinatura:

            [MENSAGEM][ASSINATURA]<0>
                       \\_____ 88 _____/
        """

        return SIGNATURE_SIZE


    @staticmethod
    def public_key_size():
        """
        Tamanho da chave pública em caracteres.
        Usado para reconhecer um convite (seção 12).
        """

        return PUBLIC_KEY_SIZE


    # =================================================
    # ASSINAR
    # =================================================

    @staticmethod
    def _to_bytes(message):
        """
        Assinar e verificar precisam converter a mensagem em bytes
        exatamente da mesma forma, senão a mesma mensagem gera
        assinaturas que não batem.
        """

        if isinstance(message, bytes):

            return message

        return str(message).encode("utf-8")


    def sign(self, message):

        """
        Assina uma mensagem.

        Retorna somente a assinatura.
        """

        signed = self.private_key.sign(

            self._to_bytes(message)

        )


        signature = signed.signature


        return base64.b64encode(
            signature
        ).decode()


    # =================================================
    # VALIDAR ASSINATURA
    # =================================================

    @staticmethod
    def verify(
        public_key,
        message,
        signature
    ):

        """
        Verifica se uma assinatura
        pertence a uma chave pública.

        NUNCA levanta exceção: chave torta, base64 quebrado ou tamanho
        errado devolvem False. A seção 15 testa a assinatura contra
        várias carteiras em sequência, e uma entrada ruim no meio da
        lista não pode derrubar a identificação.
        """

        if not public_key or not signature:

            return False

        try:

            chave = base64.b64decode(public_key)

            assinatura = base64.b64decode(signature)

        except Exception:

            return False

        if len(chave) != RAW_PUBLIC_KEY_SIZE:

            return False

        if len(assinatura) != RAW_SIGNATURE_SIZE:

            return False

        try:

            VerifyKey(chave).verify(

                GhostIdentity._to_bytes(message),

                assinatura

            )

            return True

        except Exception:

            return False


    @staticmethod
    def find_signer(message, signature, public_keys):
        """
        Seção 15 - descobre a qual carteira a assinatura pertence.

        Recebe as chaves candidatas (trusted + candidates); quem decide
        o que entra nessa lista é o neighbors.py, não este módulo.

        Retorna a chave pública ou None (mensagem descartada).
        """

        if not public_keys:

            return None

        for chave in public_keys:

            if GhostIdentity.verify(chave, message, signature):

                return chave

        return None


    # =================================================
    # CONVITE DE CARTEIRA
    # =================================================

    def create_invite(self):

        """
        Estrutura:

        CHAVE_PUBLICA
        +
        ASSINATURA
        +
        <0>

        A assinatura é feita sobre a própria chave pública: é ela que
        prova posse da carteira anunciada (seção 18, item 1).
        """

        public = self.get_public_key()


        signature = self.sign(
            public
        )


        invite = (

            public
            +
            signature
            +
            END_MARKER

        )


        return invite


    # =================================================
    # VALIDAR CONVITE
    # =================================================

    @staticmethod
    def validate_invite(
        public_key,
        signature
    ):

        """
        O convite é válido se:

        assinatura corresponde
        à chave pública.
        """

        return GhostIdentity.verify(

            public_key,

            public_key,

            signature

        )


    @staticmethod
    def parse_invite(packet):
        """
        Separa e valida um convite recebido.

        Retorna {"public_key": ...} se válido, ou None.
        """

        if not packet:

            return None

        texto = str(packet)

        if texto.endswith(END_MARKER):

            texto = texto[:-len(END_MARKER)]

        if len(texto) != PUBLIC_KEY_SIZE + SIGNATURE_SIZE:

            return None

        public_key = texto[:PUBLIC_KEY_SIZE]

        signature = texto[PUBLIC_KEY_SIZE:]

        if not GhostIdentity.validate_invite(public_key, signature):

            return None

        return {

            "public_key": public_key

        }


    @staticmethod
    def looks_like_invite(content, signature):
        """
        Um convite se identifica sozinho: o conteúdo tem exatamente o
        tamanho de uma chave pública E a assinatura fecha com esse
        mesmo conteúdo tratado como chave.

        O documento não define um campo de tipo no pacote, e essa é a
        forma de distinguir convite de mensagem comum sem inventar um
        cabeçalho novo — é literalmente a pergunta da seção 18:
        "a assinatura corresponde à chave pública?"
        """

        if not content or len(content) != PUBLIC_KEY_SIZE:

            return False

        return GhostIdentity.verify(content, content, signature)


# =====================================================
# TESTE
# =====================================================


if __name__ == "__main__":


    node = GhostIdentity()


    print(
        "PUBLIC KEY:"
    )

    print(
        node.get_public_key()
    )

    print("  tamanho:", len(node.get_public_key()), "caracteres")


    message = "HELLO_GHOST"


    signature = node.sign(
        message
    )


    print(
        "\nSIGNATURE:"
    )

    print(
        signature
    )

    print("  tamanho:", len(signature),
          "caracteres | signature_size() =", node.signature_size())


    valid = GhostIdentity.verify(

        node.get_public_key(),

        message,

        signature

    )


    print(
        "\nVALID:"
    )

    print(
        valid
    )


    print("\nASSINATURA TROCADA (seção 16):")

    outro = GhostIdentity(key_file="teste_outro_no.key")

    nova = outro.sign(message)

    print("  mesma mensagem, assinatura do outro nó")

    print("  a antiga ainda valida?",
          GhostIdentity.verify(node.get_public_key(), message, nova))

    print("  a nova valida com a chave dele?",
          GhostIdentity.verify(outro.get_public_key(), message, nova))


    print("\nSEÇÃO 13 - SEPARAR CONTANDO DE TRÁS PARA FRENTE:")

    pacote = message + signature + END_MARKER

    corpo = pacote[:-len(END_MARKER)]

    print("  mensagem  :", corpo[:-GhostIdentity.signature_size()])

    print("  assinatura:", corpo[-GhostIdentity.signature_size():][:20], "...")


    invite = node.create_invite()


    print(
        "\nINVITE:"
    )

    print(
        invite
    )

    print("  válido?", GhostIdentity.parse_invite(invite) is not None)

    print("  reconhecido como convite?",
          GhostIdentity.looks_like_invite(

              invite[:-len(END_MARKER)][:PUBLIC_KEY_SIZE],

              invite[:-len(END_MARKER)][PUBLIC_KEY_SIZE:]

          ))

    print("  mensagem comum é confundida com convite?",
          GhostIdentity.looks_like_invite(message, signature))


    print("\nSEÇÃO 15 - DE QUEM É ESTA ASSINATURA:")

    lista = [outro.get_public_key(), node.get_public_key()]

    achado = GhostIdentity.find_signer(message, signature, lista)

    print("  encontrada:", achado == node.get_public_key())

    print("  assinatura de estranho:",
          GhostIdentity.find_signer(message, "A" * 88, lista))


    try:

        os.remove("teste_outro_no.key")

    except OSError:

        pass
