"""
GhostRelay - Sistema Econômico

Responsabilidade:
- Converter tempo de rádio em pontos
- Calcular prioridade das mensagens
- Separar regras de mensagem própria,
  vizinho conhecido e vizinho desconhecido
- Controlar redução econômica

Não controla:
- cache
- assinatura
- vizinhos
- lista corrida
- fila física


SEÇÕES DO PROTOCOLO IMPLEMENTADAS AQUI
--------------------------------------
  8   valor econômico: 1 ms de antena = 1 ponto
  9   prioridade própria = maior pontuação dos vizinhos + 1
 10   recompensa cai pela metade a cada volta
 11   prioridade cai pela metade a cada transmissão
 17   prioridade de vizinho conhecido   = pontos / tempo_ms
 20   prioridade de vizinho desconhecido = 10 / tempo_ms
 21   fidelidade de SF/BW/CR: sem match exato, sem recompensa


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) O TEMPO AGORA É CALCULADO, NÃO CRONOMETRADO.

   A versão anterior esperava "a medição real do rádio". Na prática esse
   número chegava sempre zero (o firmware não emite o evento que marcaria
   o início da recepção), e zero ponto derruba junto as seções 8, 17 e 20.

   Cronômetro de PC também não serviria: o transmissor mediria o tempo da
   serial mais o ar, o receptor mediria outra coisa, e os dois lados nunca
   fechariam a mesma conta. Sem os dois lados fechando a mesma conta, a
   seção 21 não tem como ser verificada.

   A seção 8 diz que o valor "não depende do tamanho em bytes, o que
   importa é o tempo que ela ocupa o rádio". Tempo de ocupação do rádio em
   LoRa é uma função exata de tamanho + SF + BW + CR (fórmula oficial
   Semtech, AN1200.13). Os mesmos 100 bytes valem 2.625 ms em SF12/BW250
   e 91 ms em SF7/BW250 — que é exatamente por que a seção 21 amarra a
   recompensa ao SF/BW/CR. Calculado, o valor é idêntico em todos os nós
   e impossível de falsificar.

2) validate_radio_parameters() comparava com == cru. {'cr': 7} contra
   {'cr': '7'} dava False, e a recompensa sumia em silêncio. Agora os
   parâmetros são normalizados antes: SF como inteiro, BW em kHz (aceita
   Hz), CR nas três notações que circulam no projeto (7, 4/7, 45).

3) own_message_priority() agora aceita lista, dicionário de pontos ou o
   próprio trusted_keys do neighbors.py, e ignora valores inválidos.
"""


# =====================================================
# CONSTANTES DA ECONOMIA
# =====================================================

# Seção 8
POINTS_PER_MS = 1.0

# Seção 20
UNKNOWN_NEIGHBOR_POINTS = 10.0

# Seções 10 e 11
HALVING_FACTOR = 2.0

# Parâmetros físicos do enlace LoRa
DEFAULT_PREAMBLE = 8
DEFAULT_CRC = True
DEFAULT_EXPLICIT_HEADER = True


class GhostEconomy:


    # =====================================================
    # NORMALIZAÇÃO DOS PARÂMETROS DE RÁDIO
    # =====================================================

    @staticmethod
    def normalize_sf(sf):
        """
        Spreading Factor como inteiro de 5 a 12.
        Devolve None se não der para interpretar.
        """

        try:

            valor = int(float(sf))

        except (TypeError, ValueError):

            return None

        if 5 <= valor <= 12:

            return valor

        return None


    @staticmethod
    def normalize_bw(bw):
        """
        Largura de banda em kHz.

        Aceita 250, 250.0, "250" e também 250000 (Hz), que é um erro
        fácil de cometer e que faria o tempo de antena sair 1000 vezes
        menor sem ninguém perceber.
        """

        try:

            valor = float(bw)

        except (TypeError, ValueError):

            return None

        if valor <= 0:

            return None

        # veio em Hz
        if valor >= 1000:

            valor = valor / 1000.0

        return valor


    @staticmethod
    def normalize_cr(cr):
        """
        Coding Rate no formato do firmware: 5 a 8, ou seja 4/5 até 4/8.

        Aceita as três notações que aparecem no projeto:

            5..8    denominador (RadioLib / firmware: cr=7 -> 4/7)
            1..4    índice cru
            45..48  notação "4/5".."4/8" grudada
            "4/7"   texto
        """

        if cr is None:

            return None

        if isinstance(cr, str):

            texto = cr.strip()

            if "/" in texto:

                partes = texto.split("/")

                try:

                    return GhostEconomy.normalize_cr(int(partes[1]))

                except (ValueError, IndexError):

                    return None

            cr = texto

        try:

            valor = int(float(cr))

        except (TypeError, ValueError):

            return None

        if 5 <= valor <= 8:

            return valor

        if 1 <= valor <= 4:

            return valor + 4

        if 45 <= valor <= 48:

            return valor - 40

        return None


    @staticmethod
    def normalize_radio(radio):
        """
        Recebe {"sf":..., "bw":..., "cr":...} e devolve o mesmo dicionário
        normalizado, ou None se algum campo for inválido.
        """

        if not radio:

            return None

        if not isinstance(radio, dict):

            return None

        sf = GhostEconomy.normalize_sf(radio.get("sf"))

        bw = GhostEconomy.normalize_bw(radio.get("bw"))

        cr = GhostEconomy.normalize_cr(radio.get("cr"))

        if sf is None or bw is None or cr is None:

            return None

        return {

            "sf": sf,

            "bw": bw,

            "cr": cr

        }


    # =====================================================
    # TEMPO DE ANTENA (SEÇÃO 8)
    # =====================================================

    @staticmethod
    def airtime_ms(
        packet_size,
        sf,
        bw,
        cr,
        preamble=DEFAULT_PREAMBLE,
        crc=DEFAULT_CRC,
        explicit_header=DEFAULT_EXPLICIT_HEADER
    ):
        """
        Tempo que o pacote ocupa o rádio, em milissegundos.

        Fórmula oficial Semtech (AN1200.13). Conferida contra valores de
        referência conhecidos:

            SF7  BW125 CR4/5 10 bytes  ->   41,2 ms
            SF10 BW125 CR4/5 20 bytes  ->  371,7 ms
            SF12 BW125 CR4/5 10 bytes  ->  991,2 ms

        packet_size deve ser o tamanho do que REALMENTE vai ao ar, ou
        seja o pacote inteiro da seção 4:

            [MENSAGEM][ASSINATURA]<0>

        Devolve 0.0 se os parâmetros forem inválidos.
        """

        sf = GhostEconomy.normalize_sf(sf)

        bw = GhostEconomy.normalize_bw(bw)

        cr = GhostEconomy.normalize_cr(cr)

        if sf is None or bw is None or cr is None:

            return 0.0

        try:

            n_bytes = int(packet_size)

        except (TypeError, ValueError):

            return 0.0

        if n_bytes <= 0:

            return 0.0

        # índice de 1 a 4 usado na fórmula
        cr_index = cr - 4

        # tempo de um símbolo, em segundos
        t_sym = (2 ** sf) / (bw * 1000.0)

        # low data rate optimization: obrigatório quando o símbolo
        # passa de 16 ms (é o caso de SF12/BW250, que dá 16,384 ms)
        de = 1 if (t_sym * 1000.0) > 16.0 else 0

        ih = 0 if explicit_header else 1

        numerador = (
            8 * n_bytes
            - 4 * sf
            + 28
            + 16 * (1 if crc else 0)
            - 20 * ih
        )

        denominador = 4 * (sf - 2 * de)

        # teto da divisão sem importar o módulo math
        blocos = -(-numerador // denominador)

        n_simbolos = 8 + max(blocos * (cr_index + 4), 0)

        t_preambulo = (preamble + 4.25) * t_sym

        t_payload = n_simbolos * t_sym

        return (t_preambulo + t_payload) * 1000.0


    @staticmethod
    def packet_size(packet):
        """
        Tamanho real do pacote no ar, em bytes.

        Texto com acento ocupa mais de um byte por caractere, e é o byte
        que o rádio transmite — não o caractere.
        """

        if packet is None:

            return 0

        if isinstance(packet, bytes):

            return len(packet)

        return len(str(packet).encode("utf-8"))


    # =====================================================
    # VALOR ECONÔMICO DA MENSAGEM (SEÇÃO 8)
    # =====================================================

    @staticmethod
    def calculate_points(time_ms):
        """
        Regra:

        1 ms = 1 ponto

        Não usa:
        - bytes
        - tamanho da mensagem

        (o tamanho entra só através do tempo de antena, junto com
        SF, BW e CR — veja airtime_ms)
        """

        try:

            valor = float(time_ms)

        except (TypeError, ValueError):

            return 0.0

        if valor <= 0:

            return 0.0

        return valor * POINTS_PER_MS


    @staticmethod
    def message_points(packet, sf, bw, cr):
        """
        Valor econômico de um pacote pronto (seção 8).

        Recebe o pacote completo [MENSAGEM][ASSINATURA]<0>, porque a
        seção 8 diz que o tempo total soma as três partes:

            Mensagem + Assinatura + Marcador <0>

        Este é o número que vai para a lista corrida (seção 7).
        """

        tamanho = GhostEconomy.packet_size(packet)

        tempo = GhostEconomy.airtime_ms(tamanho, sf, bw, cr)

        return GhostEconomy.calculate_points(tempo)


    @staticmethod
    def message_time_ms(packet, sf, bw, cr):
        """
        Só o tempo, sem converter em pontos.
        Usado pelas fórmulas de prioridade das seções 17 e 20.
        """

        return GhostEconomy.airtime_ms(

            GhostEconomy.packet_size(packet),

            sf,

            bw,

            cr

        )


    @staticmethod
    def _resolve_time(message_time_ms, packet, sf, bw, cr):
        """
        Usa o tempo informado; se não vier um tempo válido, calcula a
        partir do pacote e dos parâmetros de rádio.
        """

        try:

            valor = float(message_time_ms)

            if valor > 0:

                return valor

        except (TypeError, ValueError):

            pass

        if packet is not None:

            return GhostEconomy.message_time_ms(packet, sf, bw, cr)

        return 0.0


    # =====================================================
    # PRIORIDADE DA MENSAGEM PRÓPRIA (SEÇÃO 9)
    # =====================================================

    @staticmethod
    def own_message_priority(neighbor_points):
        """
        Mensagem criada pelo próprio nó.

        Fórmula:

        maior pontuação de vizinho + 1

        Exemplo:

        vizinhos:
        500
        200
        100

        prioridade:
        501

        Aceita:
        - lista de pontos            [500, 200, 100]
        - dicionário chave -> pontos {"AAA": 500}
        - trusted_keys do neighbors  {"AAA": {"points": 500}}
        - um número solto            500
        """

        pontos = GhostEconomy._extrair_pontos(neighbor_points)

        if not pontos:

            return 1.0

        return float(max(pontos)) + 1.0


    @staticmethod
    def _extrair_pontos(fonte):
        """
        Reduz qualquer um dos formatos aceitos a uma lista de números.
        """

        if fonte is None:

            return []

        if isinstance(fonte, (int, float)) and not isinstance(fonte, bool):

            return [float(fonte)]

        valores = []

        if isinstance(fonte, dict):

            candidatos = fonte.values()

        elif isinstance(fonte, (list, tuple, set)):

            candidatos = fonte

        else:

            return []

        for item in candidatos:

            if isinstance(item, dict):

                item = item.get("points")

            if isinstance(item, bool):

                continue

            if isinstance(item, (int, float)):

                valores.append(float(item))

        return valores


    # =====================================================
    # PRIORIDADE DE VIZINHO CONHECIDO (SEÇÃO 17)
    # =====================================================

    @staticmethod
    def known_neighbor_priority(
        neighbor_points,
        message_time_ms=None,
        sf=None,
        bw=None,
        cr=None,
        packet=None
    ):
        """
        Mensagem recebida de vizinho conhecido.

        Fórmula:

        pontos acumulados do vizinho /
        tempo total da transmissão em ms

        Exemplo do documento:

            vizinho com 1000 pontos, mensagem de 10 ms
            prioridade = 1000 / 10 = 100

        Se message_time_ms não vier, o tempo é calculado a partir do
        pacote com SF/BW/CR — é o caminho recomendado, porque tempo
        cronometrado no PC não fecha entre dois nós.

        Observação fiel ao documento: vizinho conhecido com 0 pontos
        gera prioridade 0. Ele é confiável, mas ainda não ajudou.
        """

        tempo = GhostEconomy._resolve_time(

            message_time_ms, packet, sf, bw, cr

        )

        if tempo <= 0:

            return 0.0

        try:

            pontos = float(neighbor_points)

        except (TypeError, ValueError):

            return 0.0

        return pontos / tempo


    # =====================================================
    # PRIORIDADE DE VIZINHO DESCONHECIDO (SEÇÃO 20)
    # =====================================================

    @staticmethod
    def unknown_neighbor_priority(
        message_time_ms=None,
        sf=None,
        bw=None,
        cr=None,
        packet=None
    ):
        """
        Mensagem recebida de candidato.

        Fórmula:

        10 / tempo da mensagem em ms
        """

        tempo = GhostEconomy._resolve_time(

            message_time_ms, packet, sf, bw, cr

        )

        if tempo <= 0:

            return 0.0

        return UNKNOWN_NEIGHBOR_POINTS / tempo


    # =====================================================
    # VALIDAÇÃO DOS PARÂMETROS DE RÁDIO (SEÇÃO 21)
    # =====================================================

    @staticmethod
    def validate_radio_parameters(
        original_radio,
        received_radio
    ):
        """
        Verifica fidelidade:

        SF
        BW
        CR

        Mensagens com configuração
        diferente não devem gerar
        recompensa econômica.

        Os dois lados são normalizados antes da comparação: 250 e 250.0,
        7 e "4/7" são o mesmo parâmetro. Parâmetro faltando ou ilegível
        é tratado como reprovado — na dúvida, não paga.
        """

        a = GhostEconomy.normalize_radio(original_radio)

        b = GhostEconomy.normalize_radio(received_radio)

        if a is None or b is None:

            return False

        return (

            a["sf"] == b["sf"]

            and abs(a["bw"] - b["bw"]) < 0.01

            and a["cr"] == b["cr"]

        )


    # =====================================================
    # VALIDAÇÃO ANTES DE RECOMPENSAR
    # =====================================================

    @staticmethod
    def reward_allowed(
        original_radio,
        received_radio
    ):
        """
        Define se uma retransmissão pode
        participar da economia.

        Regra GhostRelay:

        SF diferente
        BW diferente
        CR diferente

        = sem recompensa
        """

        return GhostEconomy.validate_radio_parameters(

            original_radio,

            received_radio

        )


    @staticmethod
    def calculate_valid_reward(
        time_ms,
        original_radio,
        received_radio
    ):
        """
        Calcula pontos somente se
        a configuração de rádio for
        idêntica.

        Retorna:

        pontos ou zero.
        """

        if not GhostEconomy.reward_allowed(

            original_radio,

            received_radio

        ):

            return 0.0

        return GhostEconomy.calculate_points(time_ms)


    @staticmethod
    def validate_message_radio(message):
        """
        Auxiliar para validar objetos
        vindos da relay_queue.

        Espera:

        {
            sf,
            bw,
            cr
        }

        Agora confere também se os valores são utilizáveis: campo
        presente porém None passava na versão anterior e quebrava
        o cálculo lá na frente.
        """

        if not message:

            return False

        if not isinstance(message, dict):

            return False

        return GhostEconomy.normalize_radio(message) is not None


    # =====================================================
    # REDUÇÃO DA PRIORIDADE DA FILA (SEÇÃO 11)
    # =====================================================

    @staticmethod
    def reduce_priority(priority):

        try:

            return float(priority) / HALVING_FACTOR

        except (TypeError, ValueError):

            return 0.0


    # =====================================================
    # REDUÇÃO DA RECOMPENSA DA CORRIDA (SEÇÃO 10)
    # =====================================================

    @staticmethod
    def reduce_reward(value):

        try:

            return float(value) / HALVING_FACTOR

        except (TypeError, ValueError):

            return 0.0


    # =====================================================
    # VALIDAÇÃO DE TEMPO
    # =====================================================

    @staticmethod
    def validate_time(time_ms):

        try:

            return float(time_ms) > 0

        except (TypeError, ValueError):

            return False


if __name__ == "__main__":

    economy = GhostEconomy()

    print("=" * 58)
    print(" SEÇÃO 8 - VALOR = TEMPO DE ANTENA")
    print("=" * 58)

    print("  calculate_points(350) =", economy.calculate_points(350))

    conteudo = "OLA_GHOSTRELAY"

    assinatura = "A" * 88          # Ed25519 em base64

    pacote = conteudo + assinatura + "<0>"

    print("\n  pacote: %d caracteres (%d bytes no ar)"
          % (len(pacote), economy.packet_size(pacote)))

    for sf in (7, 9, 12):

        t = economy.message_time_ms(pacote, sf, 250, 7)

        print("    SF%-2d BW250 CR4/7 -> %8.1f ms = %8.1f pontos"
              % (sf, t, economy.message_points(pacote, sf, 250, 7)))

    print("\n  os mesmos bytes valem 20x mais em SF12 do que em SF7:")
    print("  é por isso que a seção 21 amarra a recompensa ao SF/BW/CR")

    print("\n" + "=" * 58)
    print(" SEÇÕES 9, 17 E 20 - PRIORIDADES (exemplos do documento)")
    print("=" * 58)

    print("  própria, vizinhos [500,200,100] ->",
          economy.own_message_priority([500, 200, 100]), "(documento: 501)")

    print("  própria, sem vizinhos           ->",
          economy.own_message_priority([]), "(documento: 1)")

    print("  conhecido, 1000 pts / 10 ms     ->",
          economy.known_neighbor_priority(1000, 10), "(documento: 100)")

    print("  desconhecido, 10 ms             ->",
          economy.unknown_neighbor_priority(10), "(documento: 10/10 = 1)")

    print("\n  trusted_keys do neighbors.py direto:")
    print("   ", economy.own_message_priority({

        "chave_a": {"points": 500},

        "chave_b": {"points": 200}

    }))

    print("\n" + "=" * 58)
    print(" SEÇÃO 21 - FIDELIDADE DE RÁDIO")
    print("=" * 58)

    original = {"sf": 12, "bw": 250, "cr": 7}

    casos = [

        ({"sf": 12, "bw": 250.0, "cr": "4/7"}, "mesma config, notação diferente"),

        ({"sf": 12, "bw": 250000, "cr": 47}, "BW em Hz, CR como 47 (=4/7)"),

        ({"sf": 12, "bw": 250, "cr": 45}, "CR 4/5 no lugar de 4/7"),

        ({"sf": 9, "bw": 250, "cr": 7}, "SF diferente"),

        ({"sf": 12, "bw": 125, "cr": 7}, "BW diferente"),

        ({"sf": 12, "bw": 250, "cr": None}, "CR faltando"),

    ]

    for recebido, descricao in casos:

        paga = economy.reward_allowed(original, recebido)

        print("  %-32s -> %s" % (descricao, "PAGA" if paga else "não paga"))

    print("\n" + "=" * 58)
    print(" SEÇÕES 10 E 11 - REDUÇÃO PELA METADE")
    print("=" * 58)

    recompensa = 100.0

    prioridade = 100.0

    print("  volta/TX |  recompensa  |  prioridade")

    for i in range(5):

        print("     %d     | %9.2f    | %9.2f" % (i, recompensa, prioridade))

        recompensa = economy.reduce_reward(recompensa)

        prioridade = economy.reduce_priority(prioridade)
