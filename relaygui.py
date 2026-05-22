#!/usr/bin/env python3
"""
GhostRelay GUI
- Uses the existing relay.py backend logic
- Fixes the Python 3.12 dataclass import issue by inserting the backend module into sys.modules
- Shows a Tkinter interface with:
  * Messages tab
  * Node List tab
  * Donation tab
  * Contacts sidebar
  * Commands / plaintext / encrypted send
"""

from __future__ import annotations

import builtins
import importlib.util
import logging
import os
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# -----------------------------------------------------------------------------
# Backend loader
# -----------------------------------------------------------------------------

def load_backend_module():
    """
    Load the relay backend (relay.py / ghostrelay.py) safely under Python 3.12.

    The important bit is putting the module into sys.modules before exec_module(),
    otherwise dataclasses and some decorators can fail during import.
    """
    here = Path(__file__).resolve().parent
    candidates = [
        here / "relay.py",
        here / "ghostrelay.py",
        Path.cwd() / "relay.py",
        Path.cwd() / "ghostrelay.py",
    ]

    backend_path = next((p for p in candidates if p.exists()), None)
    if backend_path is None:
        raise FileNotFoundError(
            "Could not find relay.py or ghostrelay.py next to the GUI script or in the current directory."
        )

    spec = importlib.util.spec_from_file_location("ghostrelay_backend", backend_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load backend module from {backend_path}")

    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # critical for dataclasses on Python 3.12+
    spec.loader.exec_module(mod)
    return mod, backend_path


backend, BACKEND_PATH = load_backend_module()

# -----------------------------------------------------------------------------
# Logger bridge: send backend log lines into the GUI
# -----------------------------------------------------------------------------

class GuiLogHandler(logging.Handler):
    def __init__(self, emit_fn):
        super().__init__()
        self.emit_fn = emit_fn

    def emit(self, record):
        try:
            msg = self.format(record)
            self.emit_fn(msg)
        except Exception:
            pass


# -----------------------------------------------------------------------------
# Runtime controller
# -----------------------------------------------------------------------------

class GhostRelayRuntime:
    def __init__(self, gui_log_callback):
        self.gui_log_callback = gui_log_callback
        self.command_queue: "queue.Queue[str | None]" = queue.Queue()
        self.stop_event = threading.Event()
        self.running = False
        self.thread: Optional[threading.Thread] = None

        self.transport = None
        self.worker = None
        self.line_queue: "queue.Queue[str | None]" = queue.Queue()
        self.stdin_like_queue = self.command_queue  # just an alias

        self._orig_print = builtins.print
        self._logger_handler = GuiLogHandler(self._log_from_backend)
        self._logger_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%H:%M:%S"))

        # Patch backend prints so its internal print() calls show up in the GUI.
        self._patch_backend_output()

    def _patch_backend_output(self):
        def gui_print(*args, **kwargs):
            sep = kwargs.get("sep", " ")
            end = kwargs.get("end", "\n")
            text = sep.join(str(a) for a in args)
            text = text + ("" if end == "" else "")
            # Strip only the trailing newline if present; GUI log adds its own.
            if text.endswith("\n"):
                text = text[:-1]
            if text:
                self.gui_log_callback(text)

        # Shadow builtins.print inside the backend module namespace.
        backend.print = gui_print  # type: ignore[attr-defined]

        # Route the backend logger into the GUI too.
        backend.log.setLevel(logging.INFO)
        backend.log.handlers = []
        backend.log.addHandler(self._logger_handler)
        backend.log.propagate = False

    def _log_from_backend(self, msg: str):
        self.gui_log_callback(msg)

    def log(self, msg: str):
        self.gui_log_callback(msg)

    def start(self):
        if self.running:
            return
        self.running = True
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._main_loop, daemon=True, name="ghostrelay-runtime")
        self.thread.start()

    def stop(self):
        self.running = False
        self.stop_event.set()
        self.command_queue.put(None)
        if self.thread:
            self.thread.join(timeout=2.5)

    def send_command(self, cmd: str):
        self.command_queue.put(cmd)

    def _start_backend_threads_if_present(self):
        for name in ("cleanup_thread", "race_watcher_thread", "expunge_watcher_thread"):
            fn = getattr(backend, name, None)
            if callable(fn):
                threading.Thread(target=fn, daemon=True, name=name).start()

    def _main_loop(self):
        # Initial state load
        try:
            backend.reload_trusted()
        except Exception as e:
            self.log(f"[BACKEND] reload_trusted failed: {e}")
        try:
            backend.reload_candidates()
        except Exception as e:
            self.log(f"[BACKEND] reload_candidates failed: {e}")
        try:
            backend.reload_contacts()
        except Exception as e:
            self.log(f"[BACKEND] reload_contacts failed: {e}")
        try:
            backend.load_processed_hash_cache()
        except Exception as e:
            self.log(f"[BACKEND] load_processed_hash_cache failed: {e}")

        self._start_backend_threads_if_present()

        self.log(f"""
╔══════════════════════════════════════════════════════════════════╗
║                   WELCOME TO {backend.PROJECT_NAME}!                      ║
║                                                                  ║
║  ID+hash FIFO · races · expunge windows · ECIES · invite         ║
║                                                                  ║
║  Time window : 20 min past · 10 min future                       ║
║  Cache FIFO  : {getattr(backend, 'CACHE_MAX', 10000)} hashes                                 ║
║  Queue TTL   : {getattr(backend, 'QUEUE_TTL_SEC', 60.0):.0f}s                              ║
║                                                                  ║
║  {getattr(backend, 'MONERO_ADDRESS', '')}                                                ║
╚══════════════════════════════════════════════════════════════════╝
""".rstrip())

        self.log(f"[START] My fingerprint  : {backend.MY_NODE_ID}")
        try:
            trusted = backend.get_trusted()
            self.log(f"[START] Trusted peers   : {list(trusted.keys()) or '(none)'}")
        except Exception:
            self.log("[START] Trusted peers   : (unavailable)")
        try:
            with backend.contacts_lock:
                self.log(f"[START] Contacts        : {len(backend._contacts)} saved")
        except Exception:
            self.log("[START] Contacts        : (unavailable)")
        try:
            self.log(f"[START] Candidates      : {len(backend.get_candidates_list())} saved")
        except Exception:
            self.log("[START] Candidates      : (unavailable)")
        self.log(f"[START] Max buffer      : {backend.MAX_BUFFER_BYTES // 1024 // 1024} MB")
        self.log(f"[START] Cache file      : {getattr(backend, 'HASH_CACHE_PATH', '(none)')}")
        self.log(f"[START] pyserial        : {'available' if getattr(backend, '_SERIAL_AVAILABLE', False) else 'NOT installed'}")
        self.log(f"[START] Primary mode    : {backend.CFG.get('connection_type', 'tcp').upper()}")
        self.log("")

        manager = backend.TransportManager(backend.CFG)
        retry_delay = 5

        while self.running:
            transport = None
            stop_event = None
            worker = None

            try:
                transport = manager.connect_next()
            except RuntimeError as e:
                self.log(f"[MAIN] {e} - retrying in {retry_delay}s...")
                time.sleep(retry_delay)
                continue

            try:
                # Stabilization for serial devices
                if isinstance(transport, backend.SerialTransport):
                    time.sleep(2.0)
                    try:
                        transport.send(b"")
                    except Exception:
                        pass

                stop_event = threading.Event()
                line_queue: "queue.Queue[str | None]" = queue.Queue()
                transport.start_reader(line_queue, stop_event)

                worker = threading.Thread(
                    target=backend.retransmit_worker,
                    args=(transport, stop_event),
                    daemon=True,
                    name="tx-worker",
                )
                worker.start()

                connection_lost = False
                while self.running and not connection_lost:
                    # Drain network lines
                    while True:
                        try:
                            line = line_queue.get_nowait()
                        except queue.Empty:
                            break
                        if line is None:
                            self.log("[MAIN] Transport disconnected")
                            connection_lost = True
                            break
                        self._dispatch_line(line)
                    if connection_lost or not self.running:
                        break

                    # Drain GUI commands
                    try:
                        cmd = self.command_queue.get_nowait()
                    except queue.Empty:
                        time.sleep(0.05)
                        continue

                    if cmd is None:
                        break

                    cmd = cmd.strip()
                    if not cmd:
                        continue

                    self._handle_command(cmd, transport)

            except Exception as e:
                self.log(f"[MAIN] Unexpected error: {e}")
            finally:
                if stop_event:
                    stop_event.set()
                if worker and worker.is_alive():
                    worker.join(timeout=1.0)
                if transport:
                    try:
                        transport.close()
                    except Exception:
                        pass

            if self.running:
                self.log(f"[MAIN] Reconnecting in {retry_delay}s...")
                time.sleep(retry_delay)

    def _dispatch_line(self, line: str):
        raw = line.strip()

        # The firmware often prefixes host-side lines with "[ESP32] ".
        if raw.startswith("[ESP32] "):
            raw = raw[len("[ESP32] "):].strip()

        # Transmission confirmation from the radio/firmware
        if "[LoRa] OK" in raw:
            backend.confirm_event.set()
            self.log(f"[ESP32] {line.strip()}")
            return

        # Radio packet lines
        if raw.startswith("[LoRa] "):
            content = raw[len("[LoRa] "):].strip()
            if content.startswith("tx "):
                if backend.handle_lora_packet(content[3:].strip()):
                    return
            else:
                if backend.handle_lora_packet(content):
                    return
                self.log(f"[ESP32] {content}")
            return

        # Invite lines can arrive without a [LoRa] prefix on some builds.
        if backend.process_invite(raw):
            return

        # Some firmwares may emit raw packets without prefixes.
        if backend.handle_lora_packet(raw):
            return

        # Fall back to plain ESP32 text.
        self.log(f"[ESP32] {raw}")

    def _handle_command(self, cmd: str, transport):
        low = cmd.lower()

        # If a plaintext message is pending confirmation, accept only yes/no.
        if getattr(self, "_pending_plaintext", None) is not None:
            if low == "yes":
                text, contact_name = self._pending_plaintext
                self._pending_plaintext = None
                if contact_name:
                    ok = backend.send_normal_message(transport, text, encrypt_to=contact_name)
                    if ok:
                        self.log(f"🔒 [SENT ENCRYPTED] to '{contact_name}'")
                    else:
                        self.log("[ERROR] Message not sent.")
                else:
                    ok = backend.send_normal_message(transport, text)
                    if ok:
                        self.log("[SENT PLAINTEXT] queued for race/window")
                    else:
                        self.log("[ERROR] Message not sent.")
            else:
                self._pending_plaintext = None
                self.log("✗ Send cancelled.")
            return

        if low == "credits":
            self._cmd_credits()
        elif low == "queue":
            self._cmd_queue()
        elif low == "trusted":
            self._cmd_trusted()
        elif low == "contacts":
            self._cmd_contacts()
        elif low == "mykey":
            backend.show_my_pubkey()
        elif low == "clear":
            self.log("\033[2J\033[H")
        elif low == "wifiscan":
            if hasattr(backend, "cmd_wifi_scan"):
                backend.cmd_wifi_scan()
            else:
                self.log("[ERROR] WiFi scan not available in backend.")
        elif low == "invite":
            try:
                backend.send_invite(transport)
                self.log("[INVITE] Invitation sent")
            except Exception as e:
                self.log(f"[ERROR] Invite failed: {e}")
        elif low == "candidates":
            backend.cmd_candidates()
        elif low == "clear_candidates":
            backend.clear_candidates()
            self.log("[CANDIDATES] All candidates cleared.")
        elif low.startswith("addnode "):
            parts = cmd.split(maxsplit=2)
            if len(parts) == 3:
                ok = backend.add_trusted_node(parts[1], parts[2])
                self.log("✓ Node added" if ok else "✗ Invalid key")
            else:
                self.log("Usage: addnode <name> <base64_key_or_PEM>")
        elif low.startswith("addcontact "):
            parts = cmd.split(maxsplit=2)
            if len(parts) == 3:
                ok = backend.add_contact(parts[1], parts[2])
                self.log("✓ Contact added" if ok else "✗ Invalid key")
            else:
                self.log("Usage: addcontact <name> <base64_key_or_PEM>")
        elif backend.is_esp_cmd(cmd):
            try:
                backend.safe_send(transport, f"{cmd}\r\n".encode("utf-8"))
                self.log(f"[CMD] {cmd}")
            except Exception as e:
                self.log(f"[CMD] Send failed: {e}")
        else:
            # Message: "text" or "text:contact"
            contact_name = None
            text = cmd
            if ":" in cmd:
                left, right = cmd.rsplit(":", 1)
                candidate = right.strip()
                if candidate and backend.get_contact(candidate):
                    text = left.strip()
                    contact_name = candidate

            if not text.strip():
                self.log("[ERROR] Empty message.")
                return

            if contact_name:
                ok = backend.send_normal_message(transport, text, encrypt_to=contact_name)
                if ok:
                    self.log(f"🔒 [SENT ENCRYPTED] to '{contact_name}'")
                else:
                    self.log("[ERROR] Message not sent.")
            else:
                # Plaintext confirmation via text input
                if len(text.encode("utf-8")) > backend.MAX_MSG_LEN:
                    self.log(f"[ERROR] Message too long (max {backend.MAX_MSG_LEN} UTF-8 bytes)")
                    return
                self.log("\n⚠️  This message is NOT encrypted.")
                self.log("    Any node on the network will be able to read it.")
                self.log("    Are you sure you want to send it? (yes / no)")
                self._pending_plaintext = (text, None)

    def _cmd_credits(self):
        with backend.trusted_lock:
            snap = sorted(backend._trusted.items(), key=lambda x: x[1].points, reverse=True)
        msg = "\n=== TRUSTED (points) ===\n"
        if snap:
            for fp, entry in snap:
                msg += f"  {fp} : {entry.points} pts\n"
        else:
            msg += "  (no trusted nodes yet)\n"
        msg += "========================\n"
        self.log(msg)

    def _cmd_queue(self):
        now = time.monotonic()
        with backend.queue_lock:
            if not backend.priority_queue:
                self.log("\n=== QUEUE empty ===\n")
                return
            snap = [backend.QueueItem.from_heap_tuple(t) for t in sorted(backend.priority_queue)]
            total_bytes = backend.current_buffer_bytes
            state_snap = {h: (s.base, s.n_tx, s.born) for h, s in backend.relay_state.items()}
        msg = f"\n=== QUEUE ({len(snap)} msgs · {total_bytes} bytes) ===\n"
        for i, item in enumerate(snap[:20]):
            base, n_tx, born = state_snap.get(item.payload_hash, (item.base, item.n_tx, item.born))
            ttl = max(0.0, backend.QUEUE_TTL_SEC - (now - born))
            msg += (
                f"  {i+1:2d}. prio={item.priority:4d} base={base:4d} tx={n_tx} ttl={ttl:4.0f}s "
                f"origin={item.origin_fp} size={item.size}b hash={item.payload_hash[:8]}...\n"
            )
        msg += "============================================\n"
        self.log(msg)

    def _cmd_trusted(self):
        t = backend.get_trusted()
        msg = "\n=== TRUSTED RELAY NODES ===\n"
        if t:
            for fp, entry in t.items():
                msg += f"  {fp} : {entry.points} pts\n"
        else:
            msg += "  (none)\n"
        msg += f"  MY ID : {backend.MY_NODE_ID}\n"
        msg += "=============================\n"
        self.log(msg)

    def _cmd_contacts(self):
        with backend.contacts_lock:
            snap = list(backend._contacts.values())
        msg = "\n=== CONTACTS ===\n"
        if snap:
            for c in sorted(snap, key=lambda x: x.name.lower()):
                msg += f"  {c.name:<24} fp={backend._fp(c.vk)}\n"
        else:
            msg += "  (no contacts saved)\n"
        msg += "================\n"
        self.log(msg)


# -----------------------------------------------------------------------------
# Tkinter UI
# -----------------------------------------------------------------------------

class GhostRelayGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("GhostRelay - LoRa Mesh Network")
        self.root.geometry("1200x700")

        self.selected_contact: Optional[str] = None
        self.runtime = GhostRelayRuntime(self.log)

        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.refresh_contacts()
        self.refresh_node_list()
        self.schedule_refreshes()

        self.runtime.start()
        self.root.mainloop()

    def setup_ui(self):
        main_pane = tk.Frame(self.root)
        main_pane.pack(fill=tk.BOTH, expand=True)

        # Sidebar
        sidebar = tk.Frame(main_pane, width=220, bg="#f0f0f0")
        sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="Contacts", bg="#f0f0f0", font=("Arial", 12, "bold")).pack(pady=5)

        self.contact_listbox = tk.Listbox(sidebar, bg="white", selectmode=tk.SINGLE)
        self.contact_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.contact_listbox.bind("<<ListboxSelect>>", self.on_contact_select)

        tk.Button(sidebar, text="Refresh Contacts", command=self.refresh_contacts).pack(pady=5)

        # Main notebook
        self.notebook = ttk.Notebook(main_pane)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.messages_tab = tk.Frame(self.notebook)
        self.nodes_tab = tk.Frame(self.notebook)
        self.donation_tab = tk.Frame(self.notebook)  # Nova aba

        self.notebook.add(self.messages_tab, text="Messages")
        self.notebook.add(self.nodes_tab, text="Node List")
        self.notebook.add(self.donation_tab, text="Donation")  # Adiciona a aba

        self.setup_messages_tab()
        self.setup_nodes_tab()
        self.setup_donation_tab()  # Configura a aba de doação

    def setup_messages_tab(self):
        self.selected_label = tk.Label(self.messages_tab, text="Mode: Public / Commands", fg="blue")
        self.selected_label.pack(pady=2)

        self.log_area = scrolledtext.ScrolledText(self.messages_tab, wrap=tk.WORD, font=("Consolas", 10))
        self.log_area.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_area.configure(state=tk.DISABLED)

        frame = tk.Frame(self.messages_tab)
        frame.pack(fill=tk.X, padx=5, pady=5)

        self.entry = tk.Entry(frame)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry.bind("<Return>", self.send_command)

        self.send_btn = tk.Button(frame, text="Send", command=self.send_command)
        self.send_btn.pack(side=tk.RIGHT)

        btn_frame = tk.Frame(self.messages_tab)
        btn_frame.pack(fill=tk.X, padx=5, pady=5)

        buttons = [
            ("Credits", "credits"),
            ("Queue", "queue"),
            ("Trusted", "trusted"),
            ("My Key", "mykey"),
            ("Contacts", "contacts"),
            ("WiFi Scan", "wifiscan"),
            ("Invite", "invite"),
            ("Candidates", "candidates"),
            ("Clear Candidates", "clear_candidates"),
        ]
        for text, cmd in buttons:
            tk.Button(btn_frame, text=text, command=lambda c=cmd: self.send_cmd(c)).pack(side=tk.LEFT, padx=2)

    def setup_nodes_tab(self):
        self.node_listbox = tk.Listbox(self.nodes_tab, bg="white", font=("Consolas", 10))
        self.node_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        tk.Button(self.nodes_tab, text="Refresh Now", command=self.refresh_node_list).pack(pady=5)

        self.node_status = tk.Label(self.nodes_tab, text="Updating every 10 seconds...", fg="gray")
        self.node_status.pack(pady=2)

    def setup_donation_tab(self):
        # Aba de doação com endereço Monero
        donate_frame = tk.Frame(self.donation_tab, bg="white")
        donate_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        tk.Label(donate_frame, text="Support GhostRelay", font=("Arial", 16, "bold"), bg="white").pack(pady=10)
        tk.Label(donate_frame, text="If you find this project useful, consider donating Monero:", bg="white").pack(pady=5)

        # Endereço Monero em uma caixa de texto selecionável
        monero_address = getattr(backend, 'MONERO_ADDRESS', '49YdksRCWR3TY2A3WopX9322EGzzxBrFv4NbTho4DCNhSzUGfnAivcJNuAqEYCFjw8EYwbk4x745XjTt1Kh5n9KbNorXSD6')
        address_text = tk.Text(donate_frame, height=3, width=70, font=("Consolas", 10), wrap=tk.WORD)
        address_text.insert(tk.END, monero_address)
        address_text.configure(state=tk.DISABLED)  # somente leitura
        address_text.pack(pady=10)

        tk.Label(donate_frame, text="Thank you for your support!", bg="white", font=("Arial", 10, "italic")).pack(pady=10)

    def log(self, msg: str):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.insert(tk.END, f"{msg}\n")
        self.log_area.see(tk.END)
        self.log_area.configure(state=tk.DISABLED)

    def refresh_contacts(self):
        self.contact_listbox.delete(0, tk.END)
        self.contact_listbox.insert(tk.END, "🔓 Public / Commands")
        with backend.contacts_lock:
            names = sorted(backend._contacts.keys())
        for name in names:
            self.contact_listbox.insert(tk.END, name)

    def refresh_node_list(self):
        self.node_listbox.delete(0, tk.END)
        with backend.trusted_lock:
            nodes = [(fp, entry.points) for fp, entry in backend._trusted.items()]
        nodes.sort(key=lambda x: x[1], reverse=True)
        for fp, pts in nodes:
            self.node_listbox.insert(tk.END, f"{fp}  ({pts} pts)")

    def schedule_refreshes(self):
        self.refresh_node_list()
        self.root.after(10000, self.schedule_refreshes)

    def on_contact_select(self, event=None):
        selection = self.contact_listbox.curselection()
        if not selection:
            self.selected_contact = None
            self.selected_label.config(text="Mode: Public / Commands")
            return

        selected = self.contact_listbox.get(selection[0])
        if selected == "🔓 Public / Commands":
            self.selected_contact = None
            self.selected_label.config(text="Mode: Public / Commands")
        else:
            self.selected_contact = selected
            self.selected_label.config(text=f"Sending to: {selected} (encrypted)")

    def send_command(self, event=None):
        cmd = self.entry.get().strip()
        if not cmd:
            return
        self.entry.delete(0, tk.END)

        # If a contact is selected in the sidebar, send encrypted
        if self.selected_contact is not None:
            low = cmd.split()[0].lower() if cmd else ""
            if low in backend.ESP_CMDS or low in {
                "credits", "queue", "trusted", "mykey", "contacts", "invite",
                "candidates", "clear_candidates", "addnode", "addcontact", "clear", "wifiscan",
            }:
                self.runtime.send_command(cmd)
                self.log(f"[GUI] Command: {cmd}")
            else:
                full_cmd = f"{cmd}:{self.selected_contact}"
                self.runtime.send_command(full_cmd)
                self.log(f"[GUI] Sending encrypted to {self.selected_contact}: {cmd}")
        else:
            # No contact selected: differentiate plaintext vs encrypted via ":"
            low = cmd.split()[0].lower() if cmd else ""
            # Check if it's a command first
            if low in {
                "credits", "queue", "trusted", "mykey", "contacts", "invite",
                "candidates", "clear_candidates", "addnode", "addcontact", "clear", "wifiscan",
            } or backend.is_esp_cmd(cmd):
                self.runtime.send_command(cmd)
                self.log(f"[GUI] Command: {cmd}")
            else:
                # It's a message. Check for ":contact" pattern
                if ":" in cmd:
                    left, right = cmd.rsplit(":", 1)
                    contact = right.strip()
                    if contact and backend.get_contact(contact):
                        # Valid encrypted message
                        self.runtime.send_command(cmd)  # e.g., "oi:nodeb"
                        self.log(f"[GUI] Sending encrypted to {contact}: {left.strip()}")
                    else:
                        # Invalid contact, treat as plaintext and let runtime ask confirmation
                        self.runtime.send_command(cmd)
                        self.log(f"[GUI] Sending public message (confirmation pending): {cmd}")
                else:
                    # Plaintext message - runtime will ask yes/no
                    self.runtime.send_command(cmd)
                    self.log(f"[GUI] Sending public message (confirmation pending): {cmd}")

    def send_cmd(self, cmd: str):
        self.runtime.send_command(cmd)

    def on_close(self):
        if messagebox.askokcancel("Exit", "Do you want to close GhostRelay?"):
            self.runtime.stop()
            self.root.destroy()


if __name__ == "__main__":
    app = GhostRelayGUI()
