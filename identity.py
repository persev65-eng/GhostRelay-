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

5) SEMENTE CORROMPIDA NO STORAGE ERA JOGADA FORA.

   A proteção que guarda a chave ilegível para análise só existia para
   o arquivo legado. Vindo do storage - que é o caminho preferido - a
   semente era descartada e o arquivo sobrescrito na hora pela carteira
   nova. Se desse para recuperar (um byte trocado, um arquivo
   truncado), a chance se perdia ali, em silêncio.

   Agora a semente ilegível é guardada antes de qualquer coisa, com
   marca de tempo no nome, e o nó avisa em letras grandes que vai
   trocar de identidade - porque isso significa perder toda a
   reputação acumulada com os vizinhos.

6) IDENTIDADE COM TIPO ERRADO NO STORAGE PASSAVA EM SILÊNCIO.

   Se o storage devolvesse qualquer coisa que não fosse texto, a
   função apenas desistia e o nó criava outra carteira sem dizer nada.

7) exportar_semente() e importar_semente() não existiam.

   Não havia como fazer backup da carteira nem restaurá-la. A chave
   privada é a identidade econômica do nó: perder o disco era perder
   tudo que os vizinhos tinham acumulado para ele.
"""


import base64
import os
import stat
import time

try:

    from nacl.signing import SigningKey, VerifyKey

    # cifragem ponta a ponta: a mesma carteira Ed25519 é convertida em
    # X25519 para cifrar. Não existe chave nova para gerenciar.
    from nacl.public import Box

    from nacl.exceptions import CryptoError

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

        # nada gravado ainda: situação normal de primeiro boot
        if saved is None or saved == {} or saved == "":

            return False

        # gravado, mas não é uma semente: também é perda de carteira,
        # e antes isso passava em silêncio
        if not isinstance(saved, str):

            print("[IDENTITY] identidade no storage tem tipo inesperado:",
                  type(saved).__name__)

            self._preservar(repr(saved), "storage")

            self._avisar_carteira_nova("storage")

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


    def _aplicar_semente(self, encoded, origem, preservar=True):
        """
        Converte a chave gravada em carteira utilizável.

        Chave corrompida não pode virar carteira nova em silêncio:
        isso seria perder a identidade sem ninguém perceber. A semente
        ilegível é guardada ANTES de qualquer coisa, para dar chance de
        recuperação.

        preservar=False para importação manual: aí a semente ruim é a
        que você digitou, e a carteira atual não tem culpa nenhuma.
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

            if preservar:

                self._preservar(encoded, origem)

                self._avisar_carteira_nova(origem)

            return False

        try:

            self.private_key = SigningKey(raw)

            self.public_key = self.private_key.verify_key

        except Exception as erro:

            print("[IDENTITY] falha ao abrir a carteira:", erro)

            if preservar:

                self._preservar(encoded, origem)

                self._avisar_carteira_nova(origem)

            return False

        return True


    def _preservar(self, conteudo, origem):
        """
        Guarda a semente ilegível antes de ela ser sobrescrita.

        Antes isto só funcionava para o arquivo legado: semente
        corrompida no storage era descartada e o arquivo era
        sobrescrito na hora pela carteira nova. Se desse para
        recuperar - um byte trocado, um arquivo truncado - a chance
        se perdia ali.
        """

        marca = time.strftime("%Y%m%d-%H%M%S")

        # veio do storage
        if origem == "storage" and self.storage:

            nome = "identity_corrompida_%s" % marca

            try:

                self.storage.save(nome, conteudo)

                print("[IDENTITY] semente ilegivel guardada em",
                      self.storage.path(nome))

                return self.storage.path(nome)

            except Exception as erro:

                print("[IDENTITY] nao consegui guardar a semente:", erro)

        # veio do arquivo legado
        if os.path.exists(self.key_file):

            # com a marca de tempo no nome, uma segunda corrupção não
            # apaga o backup da primeira
            destino = "%s.corrompido-%s" % (self.key_file, marca)

            try:

                os.replace(self.key_file, destino)

                print("[IDENTITY] chave ilegivel movida para", destino)

                return destino

            except OSError:

                pass

        return None


    def _avisar_carteira_nova(self, origem):
        """
        Trocar de carteira não é detalhe: é o nó deixando de ser quem
        era para todos os vizinhos.
        """

        print("""
==================================================
 ATENCAO: A CARTEIRA VAI SER SUBSTITUIDA
==================================================
 A carteira anterior nao pode ser lida (%s).
 A semente ilegivel foi guardada ao lado.

 O no vai subir com OUTRA identidade. Isso quer dizer:

   - os pontos que os vizinhos acumularam para ele
     deixam de valer
   - ele volta a ser um vizinho desconhecido
     (secoes 18 e 19)
   - precisa mandar convite e ser promovido de novo

 Se voce tem um backup da semente, encerre o no e
 restaure antes de continuar:

     no = GhostIdentity()
     no.importar_semente("<semente em base64>")
==================================================
""" % origem)


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
    # CIFRAGEM PONTA A PONTA (mensagem e confirmação)
    # =================================================
    #
    # Caixa autenticada (crypto_box do NaCl: X25519 + XSalsa20-Poly1305)
    # entre a minha carteira e a do contato. Ela faz duas coisas ao
    # mesmo tempo: só o destinatário consegue abrir, e abrir PROVA quem
    # criou - a chave privada do autor entra na conta. Por isso a
    # "assinatura do autor" vai fundida na própria cifragem, em vez de
    # ocupar 64 bytes a mais dentro do bloco.
    #
    # Sobrecarga: 24 de nonce + 16 de autenticação = 40 bytes.

    BOX_SOBRECARGA = 40


    def _box_com(self, chave_publica):
        """
        Caixa com um contato. A chave compartilhada é calculada uma vez
        por contato e guardada: abrir cada pacote recebido testa todos
        os contatos, e recalcular o X25519 a cada teste seria caro.
        """

        if getattr(self, "_boxes_dono", None) is not self.private_key:

            # carteira trocou (importação de semente): nada do cache vale
            self._boxes = {}

            self._boxes_dono = self.private_key

        box = self._boxes.get(chave_publica)

        if box is not None:

            return box

        try:

            verify = VerifyKey(base64.b64decode(chave_publica))

            box = Box(

                self.private_key.to_curve25519_private_key(),

                verify.to_curve25519_public_key()

            )

        except Exception:

            return None

        self._boxes[chave_publica] = box

        return box


    def cifrar_para(self, chave_publica, dados):
        """
        Bloco que só a dona de chave_publica consegue abrir.
        Devolve bytes (nonce + texto cifrado + autenticação) ou None.
        """

        box = self._box_com(chave_publica)

        if box is None:

            return None

        return bytes(box.encrypt(bytes(dados)))


    def abrir_de(self, chave_publica, bloco):
        """
        Abre um bloco que teria vindo de chave_publica.
        None se não abrir - não era para mim, ou não era dela.
        """

        box = self._box_com(chave_publica)

        if box is None:

            return None

        try:

            return box.decrypt(bytes(bloco))

        except (CryptoError, ValueError, TypeError):

            return None


    def abrir_de_algum(self, chaves, bloco):
        """
        Testa o bloco contra cada chave da lista.

        Devolve (chave, dados) de quem abriu, ou (None, None).

        É assim que o nó descobre se é o destinatário: o pacote não diz
        para quem é. Se nenhum contato abre, a mensagem não é para mim -
        sigo como relay.
        """

        for chave in chaves:

            dados = self.abrir_de(chave, bloco)

            if dados is not None:

                return chave, dados

        return None, None


    @staticmethod
    def chave_publica_valida(chave):
        """
        44 caracteres de base64 que decodificam para uma chave Ed25519.
        """

        if not isinstance(chave, str) or len(chave) != PUBLIC_KEY_SIZE:

            return False

        try:

            raw = base64.b64decode(chave, validate=True)

            VerifyKey(raw)

            return len(raw) == 32

        except Exception:

            return False


    # =================================================
    # BACKUP DA CARTEIRA
    # =================================================

    def exportar_semente(self):
        """
        A semente em base64. É a carteira INTEIRA: quem tem isto é o nó.

        Guarde fora da máquina se a reputação do nó importa - é a única
        forma de recuperar a identidade depois de um disco perdido ou de
        um arquivo corrompido.
        """

        return base64.b64encode(

            bytes(self.private_key)

        ).decode()


    def importar_semente(self, semente):
        """
        Substitui a carteira atual pela semente informada e grava.

        Devolve False sem tocar em nada se a semente for inválida: a
        culpa seria do texto digitado, não da carteira que está lá.
        """

        anterior = self.private_key

        if not self._aplicar_semente(semente, "importacao", preservar=False):

            self.private_key = anterior

            self.public_key = anterior.verify_key if anterior else None

            print("[IDENTITY] semente invalida; a carteira atual foi mantida")

            return False

        self.save_wallet()

        print("[IDENTITY] carteira restaurada:", self.get_short_id())

        return True


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


    print("\nBACKUP DA CARTEIRA:")

    semente = node.exportar_semente()

    print("  semente:", semente[:24] + "...")

    copia = GhostIdentity(key_file="teste_restaurada.key")

    print("  carteira nova   :", copia.get_short_id())

    copia.importar_semente(semente)

    print("  apos restaurar  :", copia.get_short_id())

    print("  e a mesma do original?",
          copia.get_public_key() == node.get_public_key())

    print("  semente invalida e recusada:",
          copia.importar_semente("nao_e_uma_semente") is False)

    print("  carteira preservada apos a recusa?",
          copia.get_public_key() == node.get_public_key())

    for lixo in ("teste_outro_no.key", "teste_restaurada.key"):

        try:

            os.remove(lixo)

        except OSError:

            pass
