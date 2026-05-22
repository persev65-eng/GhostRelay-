#!/usr/bin/env python3
"""
WebSocket bridge entre navegador (HTML) e o relay.py (porta 9999).
Compatível com websockets >= 13.0
"""

import asyncio
import websockets
import socket

RELAY_HOST = "127.0.0.1"
RELAY_PORT = 9999
WS_HOST = "localhost"
WS_PORT = 8765

connected_ws = set()

async def relay_to_ws(websocket):
    """Conecta ao relay.py e faz a ponte bidirecional."""
    connected_ws.add(websocket)
    print(f"[WS] Client connected (total: {len(connected_ws)})")

    try:
        # Conecta ao relay (TCP)
        reader, writer = await asyncio.open_connection(RELAY_HOST, RELAY_PORT)
        print("[WS] Connected to relay.py")
    except Exception as e:
        print(f"[WS] Cannot connect to relay.py: {e}")
        await websocket.send("ERROR: Cannot connect to relay.py")
        connected_ws.discard(websocket)
        return

    async def forward_from_relay():
        """Lê do relay e envia para o websocket."""
        while True:
            try:
                data = await reader.readline()
                if not data:
                    break
                line = data.decode("utf-8", errors="replace").strip()
                if line:
                    await websocket.send(line)
            except Exception:
                break
        print("[WS] relay connection closed")
        await websocket.close()

    async def forward_to_relay():
        """Lê do websocket e envia para o relay."""
        try:
            async for message in websocket:
                # Envia mensagem com quebra de linha (protocolo do relay)
                writer.write((message + "\n").encode("utf-8"))
                await writer.drain()
        except Exception:
            pass

    # Cria tarefas simultâneas
    task1 = asyncio.create_task(forward_from_relay())
    task2 = asyncio.create_task(forward_to_relay())

    await asyncio.gather(task1, task2, return_exceptions=True)

    writer.close()
    await writer.wait_closed()
    connected_ws.discard(websocket)
    print(f"[WS] Client disconnected (total: {len(connected_ws)})")


async def main():
    print(f"[WS] Starting WebSocket bridge on ws://{WS_HOST}:{WS_PORT}")
    async with websockets.serve(relay_to_ws, WS_HOST, WS_PORT):
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
