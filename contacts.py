#!/usr/bin/env python3

"""
GhostRelay - Lista de Contatos

Responsabilidade:

- Guardar as carteiras com quem este nó troca mensagens cifradas
  (pessoas e sites)
- Guardar os pontos de contato de cada uma
- Persistir tudo

Não controla:
- vizinhos de rádio (isso é o neighbors.py)
- cifragem (isso é o identity.py)
- rádio


CONTATO NÃO É VIZINHO
---------------------
Vizinho é quem o meu rádio escuta: entra por convite, que é de um
salto só, e acumula pontos por retransmitir.

Contato é ponta a ponta: é para quem eu cifro mensagem, e pode estar a
muitos saltos de distância. Entra por registro - manual, ou por pedido
de um site ou programa ligado ao nó. Os pontos de contato são outra
contabilidade: o autor credita o destinatário quando a confirmação de
entrega chega, com o valor da mensagem.

Os pontos que EU tenho registrados para um contato decidem com que
prioridade eu envio as confirmações das mensagens DELE:

    prioridade = max(1, pontos do contato) x tempo da mensagem
                 / tempo da confirmação

Quem confirma as minhas mensagens acumula pontos comigo, e eu passo a
confirmar as dele primeiro. O piso 1 é o que permite a primeira
confirmação entre dois nós que nunca se falaram.


REGISTRO SEM PERGUNTAR
----------------------
Por decisão de projeto, um pedido de registro vindo da aplicação
(site em HTML, programa) é aceito sem confirmação do usuário.
Ainda falta a camada de segurança que vai perguntar antes.
"""

import threading
import time

try:

    from identity import GhostIdentity

except Exception:

    GhostIdentity = None


CATEGORIAS = ("pessoa", "site")


class ContactBook:


    def __init__(self, storage=None):

        self.storage = storage

        self.lock = threading.RLock()

        # chave publica -> dados do contato
        self.contatos = {}

        self.load()


    # =================================================
    # REGISTRO
    # =================================================

    def add(self, chave, nome=None, categoria="pessoa", origem="manual"):
        """
        Registra ou atualiza um contato.

        Devolve os dados do contato, ou None se a chave for inválida.
        Registrar de novo NÃO zera os pontos já acumulados.
        """

        chave = str(chave or "").strip()

        if GhostIdentity and not GhostIdentity.chave_publica_valida(chave):

            print("[CONTATOS] chave publica invalida, recusada:", chave[:12])

            return None

        categoria = str(categoria or "pessoa").lower()

        if categoria not in CATEGORIAS:

            categoria = "pessoa"

        with self.lock:

            existente = self.contatos.get(chave)

            if existente:

                if nome:

                    existente["nome"] = str(nome)[:64]

                existente["categoria"] = categoria

                self.save()

                return dict(existente)

            contato = {

                "chave": chave,

                "nome": str(nome)[:64] if nome else chave[:12],

                "categoria": categoria,

                "origem": str(origem or "manual"),

                "pontos": 0.0,

                "criado": time.time(),

                "mensagens_confirmadas": 0

            }

            self.contatos[chave] = contato

            self.save()

        print("[CONTATOS] registrado: %s (%s, %s)"
              % (contato["nome"], categoria, origem))

        return dict(contato)


    def remove(self, chave_ou_nome):

        chave = self.find(chave_ou_nome)

        if not chave:

            return False

        with self.lock:

            self.contatos.pop(chave, None)

            self.save()

        return True


    # =================================================
    # CONSULTA
    # =================================================

    def find(self, chave_ou_nome):
        """
        Aceita a chave inteira, o começo dela (12+ caracteres) ou o nome.
        Devolve a chave pública, ou None. Nome repetido não resolve:
        é ambíguo demais para escolher sozinho a quem cifrar.
        """

        alvo = str(chave_ou_nome or "").strip()

        if not alvo:

            return None

        with self.lock:

            if alvo in self.contatos:

                return alvo

            achados = [

                c for c, d in self.contatos.items()

                if d["nome"] == alvo or (len(alvo) >= 12 and c.startswith(alvo))

            ]

        return achados[0] if len(achados) == 1 else None


    def exists(self, chave):

        with self.lock:

            return chave in self.contatos


    def get(self, chave):

        with self.lock:

            c = self.contatos.get(chave)

            return dict(c) if c else None


    def chaves(self):

        with self.lock:

            return list(self.contatos.keys())


    def nome(self, chave):

        with self.lock:

            c = self.contatos.get(chave)

            return c["nome"] if c else (chave or "?")[:12]


    def listar(self):

        with self.lock:

            return [

                {"chave": d["chave"], "nome": d["nome"],
                 "categoria": d["categoria"], "pontos": round(d["pontos"], 1)}

                for d in self.contatos.values()

            ]


    def size(self):

        with self.lock:

            return len(self.contatos)


    # =================================================
    # PONTOS DE CONTATO
    # =================================================

    def get_points(self, chave):

        with self.lock:

            c = self.contatos.get(chave)

            return c["pontos"] if c else 0.0


    def add_points(self, chave, pontos):
        """
        Crédito do autor para o destinatário, quando a confirmação de
        entrega chega. Devolve o novo total, ou None se não é contato.
        """

        with self.lock:

            c = self.contatos.get(chave)

            if not c:

                return None

            c["pontos"] += float(pontos)

            c["mensagens_confirmadas"] += 1

            self.save()

            return c["pontos"]


    # =================================================
    # PERSISTÊNCIA
    # =================================================

    def load(self):

        if not self.storage:

            return

        try:

            dados = self.storage.load("contacts", {}) or {}

        except Exception:

            return

        with self.lock:

            for chave, d in dados.items():

                if not isinstance(d, dict):

                    continue

                d.setdefault("chave", chave)

                d.setdefault("nome", chave[:12])

                d.setdefault("categoria", "pessoa")

                d.setdefault("origem", "manual")

                d.setdefault("pontos", 0.0)

                d.setdefault("criado", time.time())

                d.setdefault("mensagens_confirmadas", 0)

                self.contatos[chave] = d


    def save(self):

        if not self.storage:

            return

        with self.lock:

            dados = {c: dict(d) for c, d in self.contatos.items()}

        try:

            self.storage.save("contacts", dados)

        except Exception as erro:

            print("[CONTATOS] nao consegui gravar:", erro)
