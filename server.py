#!/usr/bin/env python3

"""
GhostRelay - Server

Camada de interface externa.

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
"""


import asyncio
import websockets
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import queue
import json


WS_PORT = 8000
HTTP_PORT = 8080


# Comunicação interna com main.py

app_tx_queue = queue.Queue()
app_rx_queue = queue.Queue()


clientes = set()

loop_global = None


# O server.py é o único servidor externo.
# websocket_server.py não deve duplicar esta função.
# Toda aplicação externa entra por esta camada.


# =====================================================
# INTERFACE TX -> MAIN
# =====================================================

def receber_aplicacao(mensagem):

    """
    Chamado quando um programa/site envia
    uma mensagem.

    main.py consumirá esta fila.
    """

    app_tx_queue.put(mensagem)



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
    """

    app_rx_queue.put(mensagem)


    if loop_global:

        asyncio.run_coroutine_threadsafe(
            enviar_websocket(
                {
                    "tipo": "rx",
                    "dados": mensagem
                }
            ),
            loop_global
        )



# =====================================================
# WEBSOCKET
# =====================================================

async def enviar_websocket(dado):

    if not clientes:
        return

    texto = json.dumps(dado)

    removidos = []

    for cliente in clientes:

        try:
            await cliente.send(texto)

        except:
            removidos.append(cliente)


    for cliente in removidos:

        clientes.discard(cliente)



async def websocket_handler(ws):

    print(
        "CLIENTE WEBSOCKET CONECTADO"
    )

    clientes.add(ws)


    try:

        async for mensagem in ws:

            print(
                "APP TX:",
                mensagem
            )

            receber_aplicacao(
                mensagem
            )


    finally:

        clientes.discard(ws)



# =====================================================
# PAGINA HTTP
# =====================================================

HTML = """
<html>
<body>

<h2>GhostRelay</h2>

<input id="msg">

<button onclick="send()">
Enviar
</button>

<pre id="log"></pre>

<script>

let ws = new WebSocket(
"ws://"+location.hostname+":8000"
);


ws.onmessage=function(e){

document.getElementById(
"log"
).innerHTML += e.data+"\\n";

};


function send(){

let m=document.getElementById(
"msg"
).value;

ws.send(m);

}

</script>

</body>
</html>
"""


class Pagina(BaseHTTPRequestHandler):

    def do_GET(self):

        self.send_response(200)

        self.send_header(
            "Content-type",
            "text/html"
        )

        self.end_headers()

        self.wfile.write(
            HTML.encode()
        )



def iniciar_http():

    servidor = HTTPServer(
        (
            "0.0.0.0",
            HTTP_PORT
        ),
        Pagina
    )

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

        await asyncio.Future()



if __name__ == "__main__":

    asyncio.run(main())
