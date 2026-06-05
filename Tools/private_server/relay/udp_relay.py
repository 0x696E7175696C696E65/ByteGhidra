"""
UDP Relay Server (Tier 2 — Multiplayer)
========================================
Relays game state packets between players in a session.
Does NOT interpret game state — pure packet forwarding.

Protocol:
  Client → Server: [session_id:4][player_id:4][payload:N]
  Server → Clients: [source_player_id:4][payload:N]

Sessions are created when the first player sends a packet.
Players join sessions by sending with the same session_id.
Sessions expire after SESSION_TIMEOUT seconds of inactivity.
"""

import socket
import threading
import time
import struct
import logging

log = logging.getLogger("Relay")

SESSION_TIMEOUT  = 300   # seconds
MAX_PACKET_SIZE  = 8192  # bytes
MAX_PLAYERS      = 12    # per session (6 for raids, 3 for fireteam, etc.)

class Session:
    def __init__(self, session_id):
        self.session_id  = session_id
        self.players     = {}   # player_id -> (addr, last_seen)
        self.created_at  = time.time()
        self.packet_count= 0
        self.lock        = threading.Lock()

    def add_player(self, player_id, addr):
        with self.lock:
            self.players[player_id] = (addr, time.time())

    def update_seen(self, player_id, addr):
        with self.lock:
            if player_id in self.players:
                self.players[player_id] = (addr, time.time())

    def get_peers(self, exclude_player_id):
        with self.lock:
            now = time.time()
            return [(pid, addr) for (pid, (addr, last)) in self.players.items()
                    if pid != exclude_player_id and (now - last) < SESSION_TIMEOUT]

    def is_expired(self):
        with self.lock:
            if not self.players:
                return (time.time() - self.created_at) > 30
            now = time.time()
            return all((now - last) > SESSION_TIMEOUT
                       for (_, last) in self.players.values())

    def player_count(self):
        with self.lock:
            return len(self.players)


class RelayServer:
    def __init__(self, host="0.0.0.0", port=7777):
        self.host     = host
        self.port     = port
        self.sessions = {}   # session_id -> Session
        self.sock     = None
        self.running  = False
        self.lock     = threading.Lock()

    def get_or_create_session(self, session_id):
        with self.lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = Session(session_id)
                log.info("New session: 0x{:08x}".format(session_id))
            return self.sessions[session_id]

    def cleanup_sessions(self):
        while self.running:
            time.sleep(30)
            with self.lock:
                expired = [sid for sid, sess in self.sessions.items()
                           if sess.is_expired()]
                for sid in expired:
                    log.info("Session expired: 0x{:08x} ({} packets)".format(
                        sid, self.sessions[sid].packet_count))
                    del self.sessions[sid]

    def get_session_stats(self):
        with self.lock:
            sessions = list(self.sessions.items())
        stats = {}
        now = time.time()
        for (sid, sess) in sessions:
            with sess.lock:
                stats[sid] = {
                    "players": len(sess.players),
                    "packets": sess.packet_count,
                    "age": now - sess.created_at,
                }
        return stats

    def handle_packet(self, data, addr):
        if len(data) < 8:
            return  # too small for header

        # Parse header: [session_id:4 BE][player_id:4 BE][payload...]
        try:
            session_id, player_id = struct.unpack(">II", data[:8])
        except struct.error:
            return

        payload = data[8:]
        session = self.get_or_create_session(session_id)

        # Register/update this player
        if session.player_count() < MAX_PLAYERS:
            session.add_player(player_id, addr)
        session.update_seen(player_id, addr)
        session.packet_count += 1

        # Forward to all other players in the session
        peers = session.get_peers(player_id)
        forward = struct.pack(">I", player_id) + payload

        for (peer_id, peer_addr) in peers:
            try:
                self.sock.sendto(forward, peer_addr)
            except Exception as e:
                log.debug("Forward failed to {}: {}".format(peer_addr, e))

    def run(self):
        self.sock    = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024*1024)
        self.sock.bind((self.host, self.port))
        self.running = True

        # Start cleanup thread
        t_cleanup = threading.Thread(target=self.cleanup_sessions,
                                      daemon=True, name="RelayCleanup")
        t_cleanup.start()

        log.info("UDP relay listening on {}:{}".format(self.host, self.port))
        log.info("Max {} players per session, {}s timeout".format(
            MAX_PLAYERS, SESSION_TIMEOUT))

        stats_time = time.time()
        total_packets = 0

        while self.running:
            try:
                self.sock.settimeout(5.0)
                data, addr = self.sock.recvfrom(MAX_PACKET_SIZE)
                self.handle_packet(data, addr)
                total_packets += 1

                # Print stats every 60s
                if time.time() - stats_time > 60:
                    with self.lock:
                        active = len(self.sessions)
                    player_count = sum(s.player_count() for s in self.sessions.values())
                    log.info("Relay stats: {} sessions, {} players, {} packets/min".format(
                        active, player_count, total_packets))
                    total_packets = 0
                    stats_time = time.time()

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    log.error("Relay error: {}".format(e))

    def stop(self):
        self.running = False
        if self.sock:
            self.sock.close()


def start_relay(host="0.0.0.0", port=7777):
    server = RelayServer(host, port)
    server.run()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format='[%(asctime)s] %(name)s: %(message)s')
    start_relay()
