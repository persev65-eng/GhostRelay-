#!/usr/bin/env python3

"""
GhostRelay - Lista Corrida

Responsabilidade:

- Registrar as MINHAS mensagens em circulação (seção 7)
- Guardar o valor de cada uma, decidido UMA vez (seção 8)
- Controlar as duas corridas de recompensa de cada mensagem
- Reter a corrida da ida até a entrega ser confirmada

Não controla:
- rádio, fila, cifragem, vizinhos (só devolve a quem pagar e quanto)


SÓ MENSAGEM PRÓPRIA ENTRA AQUI
------------------------------
Relay nunca paga relay. Só o autor paga.

Se um relay pagasse, o autor ganharia pontos infinitos: B retransmite a
mensagem de A e a registra na própria corrida; A repete a mensagem;
B vê a mensagem na corrida dele e paga A - pela mensagem do próprio A.
Cada mensagem nova que A cria vira uma fonte de pagamento que ele
ordenha repetindo, sem nunca carregar nada de ninguém.


AS DUAS CORRIDAS
----------------
Cada mensagem abre duas corridas do MESMO valor (1 ms de antena = 1
ponto), e as duas funcionam igual - posição 1 leva 100%, posição 2
leva 50%, e assim por diante (seção 10):

    IDA    quem retransmitiu a minha mensagem (eu ouvi voltar)
    VOLTA  quem me entregou a confirmação do destinatário

A corrida da IDA fica RETIDA: as posições são ocupadas normalmente -
cada retorno consome uma posição e divide o valor da próxima -, mas
ninguém recebe até a primeira confirmação chegar. Se ela nunca chegar,
ninguém recebe nunca. Depois que chega, paga o acumulado e passa a
pagar na hora.

A corrida da VOLTA paga na hora: quem traz a confirmação já provou a
entrega.

Quando a primeira confirmação chega, o destinatário também recebe, em
pontos de CONTATO, o valor da mensagem - uma vez só por mensagem, por
mais cópias da confirmação que cheguem.


DOIS HASHES POR MENSAGEM
------------------------
    hash           do bloco cifrado. Igual em todos os saltos (só a
                   assinatura de fora muda), e é o que os relays veem.
                   Reconhece a mensagem voltando.

    hash_conteudo  do texto em claro. Só autor e destinatário
                   conhecem. É o que a confirmação carrega.

E, depois da confirmação, um terceiro índice:

    hash_confirmacao  do bloco da confirmação, para reconhecer as
                      próximas cópias dela sem precisar decifrar de novo.
"""

import threading
import time

from collections import OrderedDict

try:

    from economy import GhostEconomy

except Exception:

    GhostEconomy = None


# quantos pagamentos ficam no histórico de cada corrida
MAX_HISTORICO = 64


def _corrida(valor):

    return {

        "atual": float(valor),     # quanto vale a PRÓXIMA posição

        "posicoes": 0,             # posições já ocupadas

        "pendentes": [],           # [chave, pontos] retidos (só na ida)

        "pagos": []                # [chave, pontos, instante]

    }


class RaceList:


    def __init__(self, storage=None, max_size=1000):

        self.storage = storage

        self.max_size = max(1, int(max_size))

        # hash do bloco da mensagem -> entrada (ordem = FIFO, seção 23)
        self.entries = OrderedDict()

        # hash do bloco da confirmação -> hash da mensagem
        self.confirmacoes = {}

        self.lock = threading.RLock()

        self.load()


    # =================================================
    # REGISTRO (seções 5, 7 e 8)
    # =================================================

    def add_message(self, msg_hash, valor, radio, hash_conteudo, destinatario):
        """
        Só mensagem PRÓPRIA. O valor é decidido aqui e nunca mais é
        recalculado: depois disso só cai pela metade a cada posição.
        """

        if not msg_hash or not hash_conteudo or not destinatario:

            return None

        radio = self._normalizar(radio)

        with self.lock:

            existente = self.entries.get(msg_hash)

            if existente:

                return existente

            entry = {

                "hash": msg_hash,

                "hash_conteudo": hash_conteudo,

                "destinatario": destinatario,

                "own": True,

                "valor": float(valor),

                "radio": radio,

                "created": time.time(),

                "confirmada": False,

                "confirmada_em": None,

                "hash_confirmacao": None,

                "contato_pago": False,

                "ida": _corrida(valor),

                "volta": _corrida(valor)

            }

            self.entries[msg_hash] = entry

            self._aparar()

        self.save()

        return entry


    def _aparar(self):

        while len(self.entries) > self.max_size:

            _, saiu = self.entries.popitem(last=False)

            if saiu.get("hash_confirmacao"):

                self.confirmacoes.pop(saiu["hash_confirmacao"], None)


    @staticmethod
    def _normalizar(radio):

        if not radio:

            return None

        if GhostEconomy:

            return GhostEconomy.normalize_radio(radio)

        return dict(radio)


    # =================================================
    # CONSULTA
    # =================================================

    def find(self, msg_hash):

        with self.lock:

            return self.entries.get(msg_hash)


    def exists(self, msg_hash):

        with self.lock:

            return msg_hash in self.entries


    def find_confirmacao(self, hash_bloco_confirmacao):
        """
        Uma cópia de confirmação que eu já reconheci antes.
        """

        with self.lock:

            msg_hash = self.confirmacoes.get(hash_bloco_confirmacao)

            return self.entries.get(msg_hash) if msg_hash else None


    def find_por_conteudo(self, hash_conteudo, destinatario):
        """
        A mensagem que uma confirmação nova está confirmando.

        Se houver mais de uma com o mesmo texto para o mesmo destinatário,
        cada confirmação liquida a mais antiga ainda não confirmada.
        """

        with self.lock:

            candidatas = [

                e for e in self.entries.values()

                if e["hash_conteudo"] == hash_conteudo

                and e["destinatario"] == destinatario

            ]

        if not candidatas:

            return None

        for e in candidatas:

            if not e["confirmada"]:

                return e

        return candidatas[0]


    def radio_confere(self, entry, radio):
        """
        Seção 21: só paga retorno que veio com EXATAMENTE os SF/BW/CR
        com que a mensagem saiu.
        """

        original = entry.get("radio")

        if not original:

            return True

        if not radio:

            return False

        if GhostEconomy:

            return GhostEconomy.reward_allowed(original, radio)

        return (original.get("sf") == radio.get("sf")
                and original.get("bw") == radio.get("bw")
                and original.get("cr") == radio.get("cr"))


    # =================================================
    # CORRIDA DA IDA (retida até a confirmação)
    # =================================================

    def retorno_ida(self, msg_hash, chave, radio):
        """
        Ouvi alguém retransmitindo a minha mensagem.

        A posição é ocupada e o valor da próxima cai pela metade na
        hora - mesmo retida. Se não caísse, um retorno antes da
        confirmação e outro depois valeriam o mesmo.

        Devolve:
            {"ok", "motivo", "posicao", "pontos", "retido"}
        retido=True: guarde, ainda não pague.
        """

        with self.lock:

            entry = self.entries.get(msg_hash)

            if entry is None:

                return {"ok": False, "motivo": "fora da lista corrida"}

            if not self.radio_confere(entry, radio):

                # não consome posição: senão bastaria transmitir numa
                # configuração barata para queimar as posições caras
                return {"ok": False, "motivo": "SF/BW/CR diferentes (secao 21)"}

            corrida = entry["ida"]

            pontos = corrida["atual"]

            corrida["posicoes"] += 1

            corrida["atual"] = pontos / 2.0

            posicao = corrida["posicoes"]

            if entry["confirmada"]:

                self._registrar_pago(corrida, chave, pontos)

                retido = False

            else:

                corrida["pendentes"].append([chave, pontos])

                retido = True

        self.save()

        return {"ok": True, "motivo": "ok", "posicao": posicao,
                "pontos": pontos, "retido": retido}


    # =================================================
    # CONFIRMAÇÃO E CORRIDA DA VOLTA
    # =================================================

    def confirmar(self, msg_hash, hash_bloco_confirmacao):
        """
        A PRIMEIRA confirmação desta mensagem chegou.

        Libera a corrida da ida e o crédito do destinatário, uma vez só.

        Devolve:
            {"primeira": bool,
             "liberar": [[chave, pontos], ...],   corrida da ida retida
             "contato": (destinatario, valor) ou None}
        """

        with self.lock:

            entry = self.entries.get(msg_hash)

            if entry is None:

                return {"primeira": False, "liberar": [], "contato": None}

            if entry["confirmada"]:

                return {"primeira": False, "liberar": [], "contato": None}

            entry["confirmada"] = True

            entry["confirmada_em"] = time.time()

            entry["hash_confirmacao"] = hash_bloco_confirmacao

            self.confirmacoes[hash_bloco_confirmacao] = msg_hash

            liberar = entry["ida"]["pendentes"]

            entry["ida"]["pendentes"] = []

            for chave, pontos in liberar:

                self._registrar_pago(entry["ida"], chave, pontos)

            contato = None

            if not entry["contato_pago"]:

                entry["contato_pago"] = True

                contato = (entry["destinatario"], entry["valor"])

        self.save()

        return {"primeira": True, "liberar": liberar, "contato": contato}


    def retorno_volta(self, msg_hash, chave, radio):
        """
        Alguém me entregou a confirmação. Paga na hora, nas posições.
        A confirmação viaja com os mesmos SF/BW/CR da mensagem.
        """

        with self.lock:

            entry = self.entries.get(msg_hash)

            if entry is None:

                return {"ok": False, "motivo": "fora da lista corrida"}

            if not self.radio_confere(entry, radio):

                return {"ok": False, "motivo": "SF/BW/CR diferentes (secao 21)"}

            corrida = entry["volta"]

            pontos = corrida["atual"]

            corrida["posicoes"] += 1

            corrida["atual"] = pontos / 2.0

            posicao = corrida["posicoes"]

            self._registrar_pago(corrida, chave, pontos)

        self.save()

        return {"ok": True, "motivo": "ok", "posicao": posicao,
                "pontos": pontos, "retido": False}


    @staticmethod
    def _registrar_pago(corrida, chave, pontos):

        corrida["pagos"].append([chave, pontos, time.time()])

        if len(corrida["pagos"]) > MAX_HISTORICO:

            del corrida["pagos"][:-MAX_HISTORICO]


    # =================================================
    # MANUTENÇÃO E INFORMAÇÃO
    # =================================================

    def remove(self, msg_hash):

        with self.lock:

            saiu = self.entries.pop(msg_hash, None)

            if saiu and saiu.get("hash_confirmacao"):

                self.confirmacoes.pop(saiu["hash_confirmacao"], None)

        if saiu:

            self.save()

        return saiu is not None


    def clear(self):

        with self.lock:

            self.entries.clear()

            self.confirmacoes.clear()

        self.save()


    def get_all(self):

        with self.lock:

            return list(self.entries.values())


    def size(self):

        with self.lock:

            return len(self.entries)


    def resumo(self):

        with self.lock:

            total = len(self.entries)

            confirmadas = sum(1 for e in self.entries.values() if e["confirmada"])

            retidos = sum(

                sum(p for _, p in e["ida"]["pendentes"])

                for e in self.entries.values()

            )

        return {"mensagens": total, "confirmadas": confirmadas,
                "aguardando": total - confirmadas,
                "pontos_retidos": round(retidos, 1)}


    # =================================================
    # PERSISTÊNCIA
    # =================================================

    def load(self):

        if not self.storage:

            return

        try:

            dados = self.storage.load_race()

        except Exception:

            return

        if not isinstance(dados, list):

            return

        descartadas = 0

        with self.lock:

            for e in dados:

                # formato antigo (mensagem em claro, sem destinatário) ou
                # entrada de mensagem RETRANSMITIDA: nenhuma das duas
                # existe mais neste protocolo
                if (not isinstance(e, dict) or "ida" not in e
                        or not e.get("own") or not e.get("destinatario")):

                    descartadas += 1

                    continue

                self.entries[e["hash"]] = e

                if e.get("hash_confirmacao"):

                    self.confirmacoes[e["hash_confirmacao"]] = e["hash"]

            self._aparar()

        if descartadas:

            print("[RACE] %d entradas do formato antigo descartadas" % descartadas)


    def save(self):

        if not self.storage:

            return

        with self.lock:

            dados = [dict(e) for e in self.entries.values()]

        try:

            self.storage.save_race(dados)

        except Exception as erro:

            print("[RACE] nao consegui gravar:", erro)
