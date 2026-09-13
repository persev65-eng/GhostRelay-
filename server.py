#!/usr/bin/env python3

"""
GhostRelay - Server

Camada de interface externa (seção 22).

Responsabilidades:
- WebSocket para aplicações
- HTTP de teste
- Entrada de mensagens do usuário
- Saída de mensagens recebidas

Não controla:
- assinatura
- hash
- cache
- economia
- corrida
- fila de retransmissão
- rádio

Fluxo:

Aplicação
   |
   v
server.py
   |
   v
main.py
   |
   v
GhostRelay Core
   |
   v
mac.py


PROTOCOLO COM A APLICAÇÃO
-------------------------
A aplicação manda texto puro (vira mensagem) ou um objeto JSON:

    {"tipo": "tx", "dados": "texto"}     manda uma mensagem
    {"tipo": "convite"}                  anuncia a carteira agora
    {"tipo": "status"}                   pede o estado do nó

O nó responde sempre em JSON:

    {"tipo": "rx", "dados": ..., "vizinho": ..., "rssi": ...}
    {"tipo": "erro", "dados": "motivo"}
    {"tipo": "status", ...}
    {"tipo": "evento", "dados": ...}


O QUE FOI CORRIGIDO NESTA VERSÃO
--------------------------------
1) COMANDO DA APLICAÇÃO VIRAVA MENSAGEM DE TEXTO.

   O handler entregava o texto cru ao main.py. Um {"tipo":"convite"}
   mandado pelo navegador chegava como string, não como objeto, e ia
   parar na rede como se fosse uma mensagem do usuário. Agora o JSON é
   interpretado aqui.

2) A APLICAÇÃO NUNCA SABIA POR QUE A MENSAGEM NÃO SAIU.

   Um texto acima de 164 caracteres não cabe em um pacote LoRa (255 -
   88 de assinatura - 3 do marcador) e era recusado lá embaixo, em
   silêncio. Agora existe canal de erro, e a página mostra o limite.

3) enviar_para_aplicacao() SÓ SABIA MANDAR TEXTO.

   Ela embrulhava tudo em {"tipo":"rx","dados":...}, então o main.py
   não tinha como passar vizinho, RSSI e SF/BW/CR junto sem virar JSON
   dentro de JSON. Agora ela aceita texto ou objeto pronto.

4) app_rx_queue CRESCIA SEM LIMITE.

   Ninguém a consome. Em um nó ligado por dias, isso é vazamento de
   memória puro. As duas filas agora têm teto.

5) enviar_websocket() ITERAVA O CONJUNTO DE CLIENTES ENQUANTO ELE
   PODIA MUDAR. Um cliente conectando durante o envio derrubava a
   entrega para todos os outros.

6) websocket_handler(ws) SÓ FUNCIONAVA NO websockets 11+.

   Nas versões anteriores o handler recebe (ws, path) e a conexão
   falhava com TypeError.

7) HTTPServer atende um cliente por vez, e a página não se reconectava
   quando o nó reiniciava.

8) O CONTADOR DA PÁGINA CONTAVA CARACTERES; O LIMITE É EM BYTES.

   maxlength="164" no navegador, mas "ç" ocupa 2 bytes e um emoji
   ocupa 4: 120 caracteres acentuados são 240 bytes. O texto passava
   pelo navegador e era recusado pelo nó. Agora a conta é em bytes,
   com os caracteres entre parênteses quando os dois números diferem,
   e o limite passa a vir do próprio nó pelo status.

9) A ROTA /rx LIA A FILA SEM LOCK.

   list(app_rx_queue.queue) enquanto outra thread escrevia nela.

10) ERRO DE SERIALIZAÇÃO SUMIA DENTRO DE UM FUTURE.

   json.dumps acontecia dentro da corotina agendada; se o objeto não
   fosse serializável, a exceção ficava guardada num Future que
   ninguém lê e a mensagem simplesmente não chegava na tela, sem
   nenhuma pista. Agora a serialização é feita na thread que chama.

11) FILA DE ENVIO CHEIA ERA SÓ UMA LINHA NO CONSOLE.

   Quem mandou a mensagem via a tela parada sem saber que ela tinha
   sido descartada. Agora o cliente recebe o aviso.

12) PORTA HTTP OCUPADA VIRAVA TRACEBACK SOLTO NUMA THREAD,

   e a página nunca subia, sem explicação.
"""


import asyncio
import json
import queue
import threading

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:

    import websockets

except ImportError:

    raise ImportError(
        "GhostRelay precisa da biblioteca websockets para a interface.\n"
        "Instale com:  pip install websockets"
    )


WS_PORT = 8000
HTTP_PORT = 8080


# Tetos das filas internas. Sem isso, um nó ligado por dias com
# ninguém lendo a saída consome memória sem parar.
MAX_TX_FILA = 500
MAX_RX_FILA = 500


# Limite de texto por mensagem, em BYTES.
# 255 bytes do pacote LoRa - 88 de assinatura - 3 do marcador <0>.
#
# Bytes, não caracteres: "ç" ocupa 2 bytes, "ã" ocupa 2, um emoji
# ocupa 4. O rádio transmite bytes, e é por byte que o pacote estoura.
# Quando o nó informa o limite dele no status, a página passa a usar
# esse valor em vez deste.
LIMITE_TEXTO = 164


# Comunicação interna com main.py

app_tx_queue = queue.Queue(maxsize=MAX_TX_FILA)
app_rx_queue = queue.Queue(maxsize=MAX_RX_FILA)


clientes = set()

loop_global = None


# main.py registra aqui uma função que devolve o estado do nó
_status_callback = None


# O server.py é o único servidor externo.
# websocket_server.py não deve duplicar esta função.
# Toda aplicação externa entra por esta camada.


def registrar_status(funcao):
    """
    O main.py registra uma função sem argumentos que devolve um dict
    com o estado do nó. É o que alimenta o botão status e a rota /status.
    """

    global _status_callback

    _status_callback = funcao


def estado_do_no():

    if not _status_callback:

        return {"erro": "no ainda nao registrou o estado"}

    try:

        return _status_callback()

    except Exception as erro:

        return {"erro": str(erro)}


# =====================================================
# INTERFACE TX -> MAIN
# =====================================================

def receber_aplicacao(mensagem):

    """
    Chamado quando um programa/site envia
    uma mensagem.

    main.py consumirá esta fila.
    """

    try:

        app_tx_queue.put_nowait(mensagem)

        return True

    except queue.Full:

        print("[SERVER] fila de envio cheia, mensagem descartada")

        return False



def obter_mensagem_tx(timeout=None):

    """
    main.py usa esta função
    para pegar mensagens novas.
    """

    try:
        return app_tx_queue.get(
            timeout=timeout
        )

    except queue.Empty:
        return None



# =====================================================
# INTERFACE MAIN -> APP
# =====================================================

def enviar_para_aplicacao(mensagem):

    """
    Chamado pelo main.py quando
    uma mensagem válida chega da rede.

    Aceita texto puro ou um objeto já montado. Com objeto, o main.py
    consegue mandar vizinho, RSSI e SF/BW/CR junto do conteúdo - antes
    tudo era embrulhado como texto e essa informação se perdia.
    """

    if isinstance(mensagem, dict):

        dado = dict(mensagem)

        dado.setdefault("tipo", "rx")

    else:

        dado = {

            "tipo": "rx",

            "dados": mensagem

        }

    try:

        app_rx_queue.put_nowait(dado)

    except queue.Full:

        # a fila é só histórico local; perder o mais antigo é melhor
        # do que parar de entregar
        try:

            app_rx_queue.get_nowait()

            app_rx_queue.put_nowait(dado)

        except queue.Empty:

            pass

    publicar(dado)


def avisar_aplicacao(tipo, dados):
    """
    Canal de aviso: erro de envio, evento do rádio, o que o nó
    precisar contar para quem está na ponta.
    """

    publicar({

        "tipo": tipo,

        "dados": dados

    })


def publicar(dado):
    """
    Agenda o envio no laço asyncio. Pode ser chamado de qualquer thread.
    """

    if not loop_global or loop_global.is_closed():

        return

    # Serializa aqui, na thread que chamou: dentro da corotina o erro
    # ficaria guardado num Future que ninguém lê, e a mensagem
    # simplesmente não apareceria na tela sem nenhuma pista.
    try:

        texto = json.dumps(dado)

    except (TypeError, ValueError) as erro:

        print("[SERVER] objeto impossivel de serializar:", erro)

        return

    try:

        asyncio.run_coroutine_threadsafe(

            _transmitir(texto),

            loop_global

        )

    except RuntimeError:

        pass


async def _transmitir(texto):
    """
    Envia um texto já pronto para todos os clientes.
    """

    for cliente in list(clientes):

        try:

            await cliente.send(texto)

        except Exception:

            clientes.discard(cliente)



# =====================================================
# WEBSOCKET
# =====================================================

async def enviar_websocket(dado):

    if not clientes:
        return

    # list(): o conjunto pode mudar durante o await se outro cliente
    # conectar ou cair no meio do envio
    await _transmitir(json.dumps(dado))



async def websocket_handler(ws, path=None):

    """
    path continua na assinatura por compatibilidade: no websockets 10 e
    11 o handler recebe dois argumentos, do 12 em diante recebe um.
    """

    print(
        "CLIENTE WEBSOCKET CONECTADO"
    )

    clientes.add(ws)


    try:

        async for mensagem in ws:

            await tratar_mensagem(ws, mensagem)


    except Exception as erro:

        print("[WS] conexao encerrada:", type(erro).__name__)

    finally:

        clientes.discard(ws)

        print("CLIENTE WEBSOCKET SAIU")


async def tratar_mensagem(ws, bruto):
    """
    Texto puro vira mensagem. JSON vira comando.
    """

    pedido = None

    try:

        pedido = json.loads(bruto)

    except (ValueError, TypeError):

        pedido = None

    if not isinstance(pedido, dict):

        # texto puro: é uma mensagem para a rede
        print("APP TX:", str(bruto)[:60])

        if not receber_aplicacao(bruto):

            await _avisar_fila_cheia(ws)

        return

    tipo = pedido.get("tipo") or pedido.get("type") or "tx"

    if tipo == "status":

        await ws.send(json.dumps({

            "tipo": "status",

            **estado_do_no()

        }))

        return

    if tipo in ("convite", "invite"):

        receber_aplicacao({"tipo": "convite"})

        return

    dados = pedido.get("dados") or pedido.get("data") or ""

    if not str(dados).strip():

        return

    print("APP TX:", str(dados)[:60])

    if not receber_aplicacao(dados):

        await _avisar_fila_cheia(ws)



async def _avisar_fila_cheia(ws):
    """
    Fila de envio cheia era só uma linha no console do nó: quem mandou
    a mensagem via a tela parada, sem saber que ela foi descartada.
    """

    try:

        await ws.send(json.dumps({

            "tipo": "erro",

            "dados": "fila de envio cheia; a mensagem foi descartada"

        }))

    except Exception:

        pass


# =====================================================
# PAGINA HTTP
# =====================================================

HTML = """<!doctype html>
<html lang="pt-br">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GhostRelay</title>
<style>
 :root{color-scheme:dark}
 body{background:#0d0f12;color:#d8dee9;margin:0;padding:18px;
      font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
 h2{margin:0;color:#8fbcbb;letter-spacing:3px;font-weight:600}
 .estado{color:#616e7c;margin:4px 0 16px;font-size:12px}
 .estado b{color:#a3be8c}
 .linha{display:flex;gap:8px;flex-wrap:wrap}
 input{flex:1;min-width:220px;background:#171a1f;color:#eceff4;
       border:1px solid #2e3440;border-radius:6px;padding:9px;font:inherit}
 input:focus{outline:none;border-color:#5e81ac}
 button{background:#2e3440;color:#8fbcbb;border:1px solid #3b4252;
        border-radius:6px;padding:9px 14px;cursor:pointer;font:inherit}
 button:hover{background:#3b4252}
 .contador{font-size:12px;color:#616e7c;margin:6px 2px 0}
 .contador.cheio{color:#bf616a}
 #log{background:#0a0c0f;border:1px solid #20242b;border-radius:8px;
      padding:12px;height:58vh;overflow:auto;margin-top:14px;
      white-space:pre-wrap;word-break:break-word}
 #log div{padding:1px 0}
 .rx{color:#a3be8c}.tx{color:#88c0d0}.ev{color:#616e7c}
 .st{color:#ebcb8b}.err{color:#bf616a}
 .meta{color:#4c566a}
</style>
</head>
<body>

<h2>GHOSTRELAY</h2>
<div class="estado" id="estado">conectando...</div>

<div class="linha">
  <input id="msg" placeholder="mensagem para a rede" autocomplete="off">
  <button onclick="enviar()">enviar</button>
  <button onclick="comando('convite')">convite</button>
  <button onclick="comando('status')">status</button>
</div>
<div class="contador" id="contador">0 / 164 bytes</div>

<div id="log"></div>

<script>
// medido em BYTES: acento ocupa 2, emoji ocupa 4. O maxlength do
// navegador conta caracteres, entao nao serve aqui - "ç" x120 passaria
// nele e seria recusado pelo no. O valor e atualizado pelo status.
let LIMITE = 164;
const bytes = (s) => new TextEncoder().encode(s).length;
let ws, log = document.getElementById('log'), campo = document.getElementById('msg');

function escrever(classe, texto, meta){
  const l = document.createElement('div');
  l.className = classe;
  l.textContent = new Date().toLocaleTimeString() + '  ' + texto;
  if (meta) {
    const m = document.createElement('span');
    m.className = 'meta';
    m.textContent = '   ' + meta;
    l.appendChild(m);
  }
  log.appendChild(l);
  log.scrollTop = log.scrollHeight;
}

function conectar(){
  ws = new WebSocket('ws://' + location.hostname + ':8000');

  ws.onopen = () => {
    document.getElementById('estado').innerHTML = '<b>conectado</b> ao no';
    comando('status');
  };

  ws.onclose = () => {
    document.getElementById('estado').textContent = 'desconectado - religando...';
    setTimeout(conectar, 2000);
  };

  ws.onmessage = (e) => {
    let d;
    try { d = JSON.parse(e.data); } catch(err) { return escrever('ev', e.data); }

    if (d.tipo === 'rx') {
      let meta = [];
      if (d.vizinho) meta.push('de ' + d.vizinho);
      if (d.classe) meta.push(d.classe);
      if (d.rssi !== undefined && d.rssi !== null) meta.push('rssi ' + d.rssi);
      if (d.sf) meta.push('SF' + d.sf);
      escrever('rx', 'RX  ' + d.dados, meta.join('  '));
    }
    else if (d.tipo === 'erro')   escrever('err', 'ERRO  ' + d.dados);
    else if (d.tipo === 'status') mostrarStatus(d);
    else if (d.tipo === 'evento') escrever('ev', String(d.dados));
    else                          escrever('ev', JSON.stringify(d));
  };
}

function mostrarStatus(d){
  if (d.limite_texto) { LIMITE = d.limite_texto; atualizarContador(); }
  document.getElementById('estado').innerHTML =
    'carteira <b>' + (d.carteira || '?') + '</b>' +
    ' | conhecidos <b>' + (d.conhecidos || 0) + '</b>' +
    ' | candidatos <b>' + (d.candidatos || 0) + '</b>' +
    ' | fila <b>' + (d.fila || 0) + '</b>' +
    ' | corrida <b>' + (d.corrida || 0) + '</b>' +
    ' | pagos <b>' + Math.round(d.pontos_pagos || 0) + '</b>';
  escrever('st', 'STATUS  ' + JSON.stringify(d));
}

function enviar(){
  const texto = campo.value.trim();
  if (!texto || !ws || ws.readyState !== 1) return;
  const n = bytes(texto);
  if (n > LIMITE) {
    escrever('err', 'ERRO  mensagem tem ' + n + ' bytes (' + texto.length +
             ' caracteres); o maximo por pacote e ' + LIMITE + ' bytes');
    return;
  }
  ws.send(JSON.stringify({tipo:'tx', dados:texto}));
  escrever('tx', 'TX  ' + texto, 'na fila de retransmissao');
  campo.value = '';
  atualizarContador();
}

function comando(t){
  if (ws && ws.readyState === 1) ws.send(JSON.stringify({tipo:t}));
}

function atualizarContador(){
  const n = bytes(campo.value);
  const c = document.getElementById('contador');
  c.textContent = n + ' / ' + LIMITE + ' bytes';
  if (n !== campo.value.length) c.textContent += '  (' + campo.value.length + ' caracteres)';
  c.className = 'contador' + (n > LIMITE ? ' cheio' : '');
}

campo.addEventListener('input', atualizarContador);
campo.addEventListener('keydown', e => { if (e.key === 'Enter') enviar(); });

conectar();
</script>
</body>
</html>"""


class Pagina(BaseHTTPRequestHandler):

    def do_GET(self):

        if self.path.startswith("/rx"):

            # o deque interno e mexido por outra thread enquanto esta
            # rota le; queue.Queue expoe o proprio mutex para isso
            with app_rx_queue.mutex:

                historico = list(app_rx_queue.queue)[-100:]

            corpo = json.dumps(historico).encode()

            tipo = "application/json"

        elif self.path.startswith("/status"):

            corpo = json.dumps(estado_do_no()).encode()

            tipo = "application/json"

        elif self.path.startswith("/favicon"):

            self.send_response(204)

            self.end_headers()

            return

        else:

            corpo = HTML.encode()

            tipo = "text/html; charset=utf-8"

        self.send_response(200)

        self.send_header("Content-type", tipo)

        self.send_header("Content-Length", str(len(corpo)))

        self.end_headers()

        try:

            self.wfile.write(corpo)

        except (BrokenPipeError, ConnectionResetError):

            # navegador fechou no meio: não é erro do nó
            pass

    def log_message(self, *args):

        # sem poluir o console com uma linha por requisição
        pass



def iniciar_http():

    # ThreadingHTTPServer: o HTTPServer simples atende um cliente por
    # vez, e uma aba aberta segurava a página para as outras
    try:

        servidor = ThreadingHTTPServer(
            (
                "0.0.0.0",
                HTTP_PORT
            ),
            Pagina
        )

    except OSError as erro:

        # antes isto virava um traceback solto numa thread e a página
        # simplesmente nunca subia
        print("[HTTP] nao consegui abrir a porta %d: %s" % (HTTP_PORT, erro))

        print("       ja existe outro no rodando nesta maquina?")

        return

    print(
        f"Pagina: http://localhost:{HTTP_PORT}"
    )

    servidor.serve_forever()



# =====================================================
# START
# =====================================================

async def main():

    global loop_global

    loop_global = asyncio.get_running_loop()


    print(
"""
==========================
 GHOSTRELAY SERVER
==========================
"""
    )


    threading.Thread(
        target=iniciar_http,
        daemon=True
    ).start()


    async with websockets.serve(
        websocket_handler,
        "0.0.0.0",
        WS_PORT
    ):

        print(
            "WEBSOCKET ONLINE :8000"
        )

        try:

            await asyncio.Future()

        except asyncio.CancelledError:

            print("SERVIDOR ENCERRADO")



if __name__ == "__main__":

    print("""
ATENCAO

Este arquivo sozinho serve a pagina, mas nao fala com o radio:
as filas de entrada e saida vivem dentro do processo do no.

Para usar a rede, rode:

    python3 main.py
""")

    try:

        asyncio.run(main())

    except KeyboardInterrupt:

        print("\nencerrado")
