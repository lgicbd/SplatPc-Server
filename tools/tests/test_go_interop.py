"""Black-box tests of the NEX server: a real server process, NintendoClients on the client side.

Every test goes through the network only, so the same tests run against both implementations:

    py -3.12 -m unittest tools.tests.test_go_interop -v                     (the Go binary)
    set SPLATOON_NEX_SERVER=python && py -3.12 -m unittest tools.tests.test_go_interop -v

The Go binary is built once, into build/tmp. The account databases are created by the Python
store, which also proves the Go server reads the existing database format.
"""
import asyncio
import contextlib
import json
import os
import pathlib
import random
import secrets
import socket
import struct
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request

from nintendo.nex import authentication, common, matchmaking, nattraversal, rmc, secure
from tools.nexlab import accounts as account_store
from tools.tests.test_server_e2e import (FakePlayer, HOST, NOTIFICATION_JOINED, PIA_PORT, PID_A, PID_B, auto_param,
                                         free_ports, free_tcp_port, password_for, write_identity)

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORK = ROOT / "build" / "tmp"
IMPLEMENTATION = os.environ.get("SPLATOON_NEX_SERVER", "go")
BINARY = WORK / ("splatoon-nex-test" + (".exe" if os.name == "nt" else ""))
SESSION_VOID = 0x80030073
SESSION_CLOSED = 0x800300DB
INVALID_USERNAME = 0x80030064
NOT_IMPLEMENTED = 0x80010002
ADMIN_TOKEN = "interop-admin-token"
TEST_TIMEOUT = 60
MAX_LOGINS_PER_IP = 60
MAX_CONNECTIONS_PER_IP = 32
LOAD_PLAYERS = 100
LOAD_WAVE = 6
_built = False


def build_binary():
    global _built
    if not _built:
        WORK.mkdir(parents=True, exist_ok=True)
        subprocess.run(["go", "build", "-o", str(BINARY), "./cmd/splatoon-nex"], cwd=ROOT, check=True)
        _built = True


def command_line():
    if IMPLEMENTATION == "python":
        return [sys.executable, "-m", "tools.nexlab.nexserver"]
    build_binary()
    return [str(BINARY)]


def find_exception(error, kind):
    """anyio wraps an error raised while connecting in an ExceptionGroup; find the real cause."""
    if isinstance(error, kind):
        return error
    for inner in getattr(error, "exceptions", []):
        found = find_exception(inner, kind)
        if found is not None:
            return found
    return None


class ProbeSink(nattraversal.NATTraversalServer):
    """Client side of protocol 3: records the probes the server forwards to this player."""
    def __init__(self):
        super().__init__()
        self.stations = []

    async def initiate_probe(self, client, station):
        self.stations.append(station)


class InteropTests(unittest.IsolatedAsyncioTestCase):
    @contextlib.asynccontextmanager
    async def server(self, mode="lab", pids=(PID_A, PID_B), natcheck=None, fill_timeout=None, idle_timeout=None,
                     test_timeout=TEST_TIMEOUT):
        """A server process, its identities or accounts, and an exit stack for the fake players."""
        WORK.mkdir(parents=True, exist_ok=True)
        tag = secrets.token_hex(4)
        paths = []
        self.port = free_ports(2)
        self.http = None
        config = {"mode": mode, "listen": "0.0.0.0" if mode == "public" else HOST, "auth_port": self.port,
                  "secure_port": self.port + 1, "natcheck": bool(natcheck)}
        if natcheck:
            config["natcheck_addresses"] = natcheck
        command = command_line()
        if mode == "public":
            database = WORK / f"interop-{tag}.sqlite3"
            paths += [database, pathlib.Path(f"{database}-wal"), pathlib.Path(f"{database}-shm")]
            store = account_store.Accounts(database)
            for pid in pids:
                store.register(pid, password_for(pid))
            store.close()
            self.http = free_tcp_port()
            config.update(advertise="203.0.113.10", accounts_db=str(database), registration="open",
                          registration_port=self.http, admin_token=ADMIN_TOKEN)
        else:
            for pid in pids:
                path = write_identity(WORK, pid, password_for(pid))
                paths.append(path)
                command += ["--identity", str(path)]
            command += ["--identity-root", str(WORK / "no-such-root")]
        if fill_timeout:
            config["fill_timeout"] = fill_timeout
        config_path = WORK / f"interop-{tag}.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        log = WORK / f"interop-{tag}.log"
        errors = WORK / f"interop-{tag}.stderr"
        paths += [config_path, log, errors]
        # A file, not a pipe: nobody reads a pipe during the test, and a full one blocks the server's logging.
        environment = dict(os.environ)
        if idle_timeout:
            environment["NEXLAB_IDLE_TIMEOUT"] = str(idle_timeout)
        with errors.open("wb") as stderr:
            process = subprocess.Popen(command + ["--config", str(config_path), "--log", str(log)], cwd=ROOT,
                                       env=environment, stdout=subprocess.DEVNULL, stderr=stderr)
        self.log_path = log
        try:
            await self.wait_ready(process, log, errors)
            async with asyncio.timeout(test_timeout), contextlib.AsyncExitStack() as stack:
                self.stack = stack
                yield
        finally:
            process.terminate()
            await asyncio.to_thread(process.wait, 15)
            for path in paths:
                with contextlib.suppress(OSError):
                    path.unlink(missing_ok=True)

    async def wait_ready(self, process, log, errors):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail("the server stopped: %s" % errors.read_text(encoding="utf-8", errors="replace"))
            with contextlib.suppress(OSError):
                if "auth " in log.read_text(encoding="utf-8", errors="replace"):
                    return
            await asyncio.sleep(0.05)
        self.fail("the server did not start")

    async def player(self, pid, local_host=None):
        player = FakePlayer(pid, password_for(pid), self.port, self.port + 1, local_host=local_host)
        await player.connect(self.stack)
        return player

    async def refusal(self, pid):
        """The code of the error refusing this player's connection."""
        try:
            await self.player(pid)
        except Exception as error:
            found = find_exception(error, common.RMCError)
            if found is None:
                raise
            return found.code()
        self.fail("the player was accepted")

    def get(self, path, token=ADMIN_TOKEN):
        request = urllib.request.Request(f"http://{HOST}:{self.http}{path}")
        if token:
            request.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    async def admin(self, path):
        return await asyncio.to_thread(self.get, path)

    async def test_login_ticket_and_register(self):
        async with self.server():
            a = await self.player(PID_A)
            self.assertEqual(a.login_response.pid, PID_A)
            self.assertEqual(a.login_response.server_name, "branch:origin/project/wup-agmj build:3_8_15_2004_0")
            station = a.login_response.connection_data.main_station
            self.assertEqual((station["address"], station["port"], station["PID"]), (HOST, self.port + 1, 2))
            self.assertEqual(a.ticket.target, 2)
            self.assertGreaterEqual(a.register_response.connection_id, 0x1001)
            public = a.register_response.public_station
            self.assertEqual(public["type"], 3)
            self.assertEqual(public["address"], "127.0.0.10")          # lab: its own loopback address
            self.assertEqual(public["RVCID"], a.register_response.connection_id)

    async def test_unknown_lab_player_is_refused(self):
        async with self.server(pids=(PID_A,)):
            self.assertEqual(await self.refusal(PID_B), INVALID_USERNAME)

    async def test_invalid_usernames_are_refused(self):
        async with self.server():
            player = FakePlayer(PID_A, password_for(PID_A), self.port, self.port + 1)
            async with rmc.connect(player.neap_settings(), HOST, self.port) as client:
                auth = authentication.AuthenticationClient(client)
                for name in ("", "abc", "0", "99999999999", "-1", "1" * 5000):
                    with self.assertRaises(common.RMCError) as caught:
                        await auth.login(name)
                    self.assertEqual(caught.exception.code(), INVALID_USERNAME, name)
                ticket = await auth.request_ticket(PID_A, 2)
                self.assertEqual(ticket.result.code(), 0x00010001)
                with self.assertRaises(common.RMCError):
                    await auth.request_ticket(PID_A, 3)

    async def test_two_players_matchmake(self):
        async with self.server():
            a = await self.player(PID_A)
            b = await self.player(PID_B)
            self.assertEqual(await a.extension.get_playing_session([a.pid]), [])
            first = await a.extension.auto_matchmake_with_param_postpone(auto_param())
            self.assertEqual((first.owner, first.host, first.num_participants), (PID_A, PID_A, 1))
            self.assertEqual(first.session_key, bytes(32))
            event = await a.sink.wait_for(1)
            self.assertEqual((event.type, event.param1, event.param2, event.param3),
                             (NOTIFICATION_JOINED, first.id, PID_A, 1))
            second = await b.extension.auto_matchmake_with_param_postpone(auto_param())
            self.assertEqual((second.id, second.num_participants), (first.id, 2))
            for event in (await a.sink.wait_for(2), await b.sink.wait_for(1)):
                self.assertEqual((event.param1, event.param2, event.param3), (first.id, PID_B, 2))

            await a.announce_pia_socket()
            urls = await b.sessions.get_session_urls(first.id)
            self.assertEqual(len(urls), 2)
            self.assertEqual((urls[0]["address"], urls[0]["port"], urls[0]["type"]), (HOST, PIA_PORT, 3))
            self.assertEqual(urls[0]["RVCID"], a.register_response.connection_id)

            details = await b.extension.find_matchmake_session_by_gathering_id_detail(first.id)
            self.assertEqual(details.id, first.id)
            await a.extension.close_participation(first.id)
            details = await b.extension.find_matchmake_session_by_gathering_id_detail(first.id)
            self.assertFalse(details.open_participation)
            await b.extension.open_participation(first.id)                # not the host: ignored
            details = await b.extension.find_matchmake_session_by_gathering_id_detail(first.id)
            self.assertFalse(details.open_participation)
            await a.extension.open_participation(first.id)
            await a.extension.update_progress_score(first.id, 42)
            await a.extension.modify_current_game_attribute(first.id, 1, 77)
            await b.extension.modify_current_game_attribute(first.id, 1, 88)   # not the host: ignored
            details = await b.extension.find_matchmake_session_by_gathering_id_detail(first.id)
            self.assertTrue(details.open_participation)
            self.assertEqual((details.progress_score, details.attribs[1]), (42, 77))

            end = matchmaking.MatchMakingClientExt(b.client)
            self.assertTrue(await end.end_participation(first.id, "bye"))
            with self.assertRaises(common.RMCError) as caught:
                await b.sessions.get_session_urls(first.id)
            self.assertEqual(caught.exception.code(), SESSION_VOID)
            self.assertFalse(await end.end_participation(0x7000000, "bye"))

    async def test_private_room_and_host_handover(self):
        async with self.server():
            a = await self.player(PID_A)
            b = await self.player(PID_B)
            create = matchmaking.CreateMatchmakeSessionParam()
            create.session.game_mode = 3
            create.session.min_participants = 1
            create.session.max_participants = 8
            create.session.participation_policy = 98
            create.session.application_data = b"room" * 1000       # several PRUDP fragments, both ways
            create.additional_participants = []
            create.gid_for_participation_check = 0
            create.options = 0
            create.join_message = "hello"
            create.num_participants = 1
            room = await a.extension.create_matchmake_session_with_param(create)
            self.assertEqual((room.owner, room.participation_policy), (PID_A, 98))
            self.assertEqual(room.application_data, b"room" * 1000)
            self.assertEqual((await a.sink.wait_for(1)).text, "hello")

            join = matchmaking.JoinMatchmakeSessionParam()
            join.gid = room.id
            join.participants = []
            join.gid_for_participation_check = 0
            join.options = 0
            join.behavior = 0
            join.user_password = ""
            join.system_password = ""
            join.join_message = "x" * 500
            join.num_participants = 1
            join.extra_participants = 0
            joined = await b.extension.join_matchmake_session_with_param(join)
            self.assertEqual(joined.id, room.id)
            self.assertEqual(len((await b.sink.wait_for(1)).text), 200)

            key = await a.extension.join_matchmake_session_ex(room.id, "", False, 1)
            self.assertEqual(key, bytes(32))
            self.assertTrue(await a.sessions.unregister_gathering(room.id))
            details = await b.extension.find_matchmake_session_by_gathering_id_detail(room.id)
            self.assertEqual((details.owner, details.host), (PID_B, PID_B))

    async def test_lab_session_stays_open_when_full(self):
        pids = [0x2000 + i for i in range(9)]
        async with self.server(pids=pids):
            players = [await self.player(pid) for pid in pids]
            ids = set()
            for player in players:
                session = await player.extension.auto_matchmake_with_param_postpone(auto_param())
                ids.add(session.id)
            self.assertEqual(len(ids), 2)       # the 9th finds the first one full

    async def test_large_report_and_unknown_method(self):
        async with self.server():
            a = await self.player(PID_A)
            await a.secure.send_report(1, b"r" * 5000)
            with self.assertRaises(common.RMCError) as caught:
                await a.secure.request_urls(1, 1)
            self.assertEqual(caught.exception.code(), NOT_IMPLEMENTED)
            self.assertEqual(await a.extension.get_playing_session([a.pid]), [])  # still alive

    async def test_public_addresses_are_the_packet_source(self):
        async with self.server(mode="public"):
            a = await self.player(PID_A, local_host="127.0.0.2")
            b = await self.player(PID_B, local_host="127.0.0.3")
            self.assertEqual(a.login_response.connection_data.main_station["address"], "203.0.113.10")
            self.assertEqual(a.register_response.public_station["address"], "127.0.0.2")
            self.assertEqual(a.register_response.public_station["port"], a.client.local_address()[1])
            first = await a.extension.auto_matchmake_with_param_postpone(auto_param())
            await b.extension.auto_matchmake_with_param_postpone(auto_param())
            pia = await a.announce_pia_socket(PIA_PORT)
            self.assertEqual(pia["port"], PIA_PORT)
            urls = await b.sessions.get_session_urls(first.id)
            self.assertEqual(urls[0]["address"], "127.0.0.2")
            self.assertEqual(urls[1]["port"], PIA_PORT)                     # the public URL follows the PIA port

    async def test_public_unknown_pid_and_ban(self):
        async with self.server(mode="public", pids=(PID_A,)):
            self.assertEqual(await self.refusal(PID_B), INVALID_USERNAME)
            a = await self.player(PID_A)
            await a.extension.auto_matchmake_with_param_postpone(auto_param())
            sessions = await self.admin("/admin/sessions")
            self.assertEqual(len(sessions["sessions"]), 1)
            self.assertEqual(sessions["players"], [f"{PID_A:08x}"])
            metrics = await asyncio.to_thread(self.get, "/metrics", None)
            self.assertEqual((metrics["players"], metrics["sessions"]), (1, 1))

    async def test_public_eight_players_fill_one_session(self):
        pids = [0x2000 + i for i in range(9)]
        async with self.server(mode="public", pids=pids):
            players = [await self.player(pid, local_host=f"127.0.1.{i + 1}") for i, pid in enumerate(pids)]
            sessions = [await p.extension.auto_matchmake_with_param_postpone(auto_param()) for p in players]
            self.assertEqual(len({s.id for s in sessions[:8]}), 1)
            self.assertEqual(sessions[7].num_participants, 8)
            self.assertFalse(sessions[7].open_participation)
            self.assertNotEqual(sessions[8].id, sessions[0].id)
            with self.assertRaises(common.RMCError) as caught:
                await players[8].extension.find_matchmake_session_by_gathering_id_detail(sessions[0].id)
            self.assertEqual(caught.exception.code(), SESSION_CLOSED)

    async def test_public_fill_window_closes_the_session(self):
        async with self.server(mode="public", fill_timeout=0.5):
            a = await self.player(PID_A, local_host="127.0.0.2")
            b = await self.player(PID_B, local_host="127.0.0.3")
            session = await a.extension.auto_matchmake_with_param_postpone(auto_param())
            await asyncio.sleep(0.9)
            other = await b.extension.auto_matchmake_with_param_postpone(auto_param())
            self.assertNotEqual(other.id, session.id)
            closed = await self.admin("/admin/sessions")
            by_id = {item["id"]: item["closed"] for item in closed["sessions"]}
            self.assertTrue(by_id[session.id])
            self.assertFalse(by_id[other.id])

    async def test_kick_disconnects_and_forgets(self):
        async with self.server(mode="public"):
            a = await self.player(PID_A, local_host="127.0.0.2")
            await a.extension.auto_matchmake_with_param_postpone(auto_param())
            await self.admin(f"/admin/kick?pid={PID_A}")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                sessions = await self.admin("/admin/sessions")
                if not sessions["players"] and not sessions["sessions"]:
                    break
                await asyncio.sleep(0.05)
            self.assertEqual(sessions["players"], [])
            self.assertEqual(sessions["sessions"], [])

    async def test_host_leaving_ends_the_session(self):
        async with self.server():
            a = await self.player(PID_A)
            b = await self.player(PID_B)
            player = FakePlayer(PID_A, password_for(PID_A), self.port, self.port + 1)
            session = await a.extension.auto_matchmake_with_param_postpone(auto_param())
            await b.extension.auto_matchmake_with_param_postpone(auto_param())
            self.assertIsNotNone(player)
            await a.client.close()
            deadline = time.monotonic() + 5
            code = None
            while time.monotonic() < deadline and code is None:
                try:
                    await b.sessions.get_session_urls(session.id)
                    await asyncio.sleep(0.05)
                except common.RMCError as error:
                    code = error.code()
            self.assertEqual(code, SESSION_VOID)

    async def test_probe_is_forwarded_only_between_session_members(self):
        async with self.server(mode="public"):
            a = await self.player(PID_A, local_host="127.0.0.2")
            b = await self.player(PID_B, local_host="127.0.0.3")
            sink = ProbeSink()
            a.client.register_server(sink)
            nat = nattraversal.NATTraversalClient(b.client)
            target = common.StationURL("prudp", PID=PID_A, RVCID=a.register_response.connection_id)
            own = common.StationURL("prudp", address="127.0.0.3", port=4242)
            await nat.request_probe_initiation_ext([target], own)      # no shared session: refused
            await asyncio.sleep(0.3)
            self.assertEqual(sink.stations, [])
            await a.extension.auto_matchmake_with_param_postpone(auto_param())
            await b.extension.auto_matchmake_with_param_postpone(auto_param())
            await nat.request_probe_initiation_ext([target], common.StationURL("prudp", address="192.0.2.9", port=1))
            await asyncio.sleep(0.3)
            self.assertEqual(sink.stations, [])                        # not its own address: refused
            await nat.request_probe_initiation_ext([target], own)
            deadline = time.monotonic() + 3
            while not sink.stations and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            self.assertEqual(sink.stations[0]["port"], 4242)

    async def test_natcheck_answers_and_gives_the_peer_port(self):
        addresses = ["127.0.0.4", "127.0.0.5"]        # lab: public mode refuses loopback addresses
        async with self.server(natcheck=addresses):
            a = await self.player(PID_A, local_host="127.0.0.2")
            b = await self.player(PID_B, local_host="127.0.0.3")
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.bind(("127.0.0.2", 0))
            probe.settimeout(3)
            own = probe.getsockname()[1]
            target = (addresses[0], 10025)
            try:
                probe.sendto(struct.pack(">IIII", 1, 0, 0, 0), target)
                data, sender = await asyncio.to_thread(probe.recvfrom, 64)
                self.assertEqual(sender, target)
                self.assertEqual(struct.unpack(">IIII", data),
                                 (1, own, 0x7F000002, 0x7F000004))
                probe.sendto(struct.pack(">IIII", 3, 0, 0, 0), target)
                data, sender = await asyncio.to_thread(probe.recvfrom, 64)
                self.assertEqual(sender[0], addresses[0])
                self.assertNotEqual(sender[1], 10025)
                probe.sendto(struct.pack(">IIII", 2, 0, 0, 0), target)
                data, sender = await asyncio.to_thread(probe.recvfrom, 64)
                self.assertEqual(sender[0], addresses[1])
                self.assertEqual(struct.unpack(">IIII", data)[3], 0x7F000005)
                probe.sendto(struct.pack(">IIII", 999, 0, 0, 0), target)   # unknown type: no answer
                probe.settimeout(0.3)
                with self.assertRaises(TimeoutError):
                    await asyncio.to_thread(probe.recvfrom, 64)
            finally:
                probe.close()
            nat = nattraversal.NATTraversalClient(a.client)
            await nat.report_nat_properties(1, 2, 3)
            session = await a.extension.auto_matchmake_with_param_postpone(auto_param())
            await b.extension.auto_matchmake_with_param_postpone(auto_param())
            urls = await b.sessions.get_session_urls(session.id)
            self.assertEqual(urls[1]["port"], own)

    async def test_login_flood_is_refused_per_address(self):
        pids = [0x2000 + i for i in range(4)]            # within the limit of tickets per player
        async with self.server(pids=pids):
            neap = FakePlayer(pids[0], password_for(pids[0]), self.port, self.port + 1).neap_settings()
            async with rmc.connect(neap, HOST, self.port) as client:
                auth = authentication.AuthenticationClient(client)
                for index in range(MAX_LOGINS_PER_IP):
                    self.assertEqual((await auth.login(str(pids[index % 4]))).pid, pids[index % 4])
                with self.assertRaises(common.RMCError) as caught:
                    await auth.login(str(pids[0]))
                self.assertEqual(caught.exception.code(), INVALID_USERNAME)

    async def test_connection_cap_is_enforced_per_address(self):
        async with self.server():
            neap = FakePlayer(PID_A, password_for(PID_A), self.port, self.port + 1).neap_settings()
            for _ in range(MAX_CONNECTIONS_PER_IP):
                await self.stack.enter_async_context(rmc.connect(neap, HOST, self.port))
            # The PRUDP handshake comes before the limit: the extra connection is closed right after it.
            extra = await self.stack.enter_async_context(rmc.connect(neap, HOST, self.port))
            await asyncio.sleep(0.3)
            with self.assertRaises(RuntimeError):
                async with asyncio.timeout(2):
                    await extra.request(10, 1, b"")

    async def test_random_datagrams_do_not_kill_the_server(self):
        generator = random.Random(0x5EED2028)
        async with self.server():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as flood:
                for index in range(10000):
                    data = generator.randbytes(generator.randrange(0, 400))
                    if index % 2 == 0:
                        data = b"\xEA\xD0\x01" + data                  # gets past the first check
                    flood.sendto(data, (HOST, self.port + index % 2))
                    if index % 500 == 0:
                        await asyncio.sleep(0)
            await asyncio.sleep(0.5)
            a = await self.player(PID_A)
            self.assertEqual(a.login_response.pid, PID_A)
            self.assertEqual(await a.extension.get_playing_session([a.pid]), [])

    @unittest.skipUnless(os.environ.get("NEXLAB_LOAD_TEST") == "1", "set NEXLAB_LOAD_TEST=1 to run the load test")
    async def test_100_players_in_waves_release_everything(self):
        pids = [0x10000000 + i for i in range(LOAD_PLAYERS)]
        failures = []
        semaphore = asyncio.Semaphore(LOAD_WAVE)

        async def run_player(index, brutal):
            # The whole connection stays in one task: anyio cancel scopes cannot be exited from another.
            pid = pids[index]
            stack = contextlib.AsyncExitStack()
            try:
                async with semaphore:
                    fake = FakePlayer(pid, password_for(pid), self.port, self.port + 1,
                                      local_host=f"127.0.0.{2 + index % 250}")
                    player = await fake.connect(stack)
                    await player.extension.auto_matchmake_with_param_postpone(auto_param())
                if brutal:
                    with contextlib.suppress(BaseException):
                        await player.client._client._socket.close()
            except BaseException as error:
                failures.append((index, error))
            finally:
                with contextlib.suppress(BaseException):
                    await stack.aclose()

        async with self.server(mode="public", pids=pids, idle_timeout=3, test_timeout=300):
            started = time.perf_counter()
            for start in range(0, LOAD_PLAYERS, LOAD_WAVE):
                wave = range(start, min(start + LOAD_WAVE, LOAD_PLAYERS))
                await asyncio.gather(*(run_player(i, i % 2 == 1) for i in wave))
                await asyncio.sleep(0.8)
            elapsed = time.perf_counter() - started
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                sessions = await self.admin("/admin/sessions")
                if not sessions["players"] and not sessions["sessions"]:
                    break
                await asyncio.sleep(0.5)
            print(f"[load] {IMPLEMENTATION}: {LOAD_PLAYERS} players, {len(failures)} failures, {elapsed:.2f} s")
            self.assertEqual(failures, [])
            self.assertEqual((sessions["players"], sessions["sessions"]), ([], []))


if __name__ == "__main__":
    unittest.main()
