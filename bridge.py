#!/usr/bin/env python3
"""
Interface Bench hardware bridge  -  Built by Nova Agentic

Serves index.html at http://localhost:8765 and streams real bus
traffic to it over a WebSocket. Every driver is optional: a protocol whose
library or device is missing simply shows "No device" in the dashboard.

  pip install aiohttp      required
  pip install pyftdi       I2C and SPI through an FT232H adapter
  pip install pysoem       EtherCAT master (admin rights; Npcap on Windows)
  pip install pyusb        USB bulk transfers (needs libusb)

Note: polling runs in Python on a desktop OS, so EtherCAT cycle times here
are best effort, not hard real-time.
"""
import argparse
import asyncio
import json
import pathlib
import socket
import threading
import time

from aiohttp import WSMsgType, web

HERE = pathlib.Path(__file__).resolve().parent
PAGE = HERE / "index.html"


def fmt(b):
    return " ".join(f"{x:02X}" for x in b)


def parse_hex(text):
    return [int(t, 16) for t in text.replace(",", " ").split()]


class Driver:
    rate = 10.0  # polls per second

    def __init__(self):
        self.lock = threading.Lock()

    def locked(self, fn, *args):
        with self.lock:
            return fn(*args)

    def open(self, cfg): raise NotImplementedError
    def poll(self): raise NotImplementedError
    def tx(self, text): raise NotImplementedError
    def close(self): pass


class I2C(Driver):
    rate = 20.0

    def open(self, cfg):
        from pyftdi.i2c import I2cController
        self.ctrl = I2cController()
        self.ctrl.configure(cfg.get("url", "ftdi://ftdi:232h/1"), frequency=float(cfg.get("speed", 400000)))
        self.addr = int(str(cfg.get("addr", "48")), 16) & 0x7F
        self.port = self.ctrl.get_port(self.addr)

    def poll(self):
        t = time.perf_counter()
        try:
            d = list(self.port.exchange([0x00], 2))  # read register 0x00
        except Exception as e:
            return dict(dir="RX", kind="nack", raw=[self.addr << 1], ok=False,
                        text=f"Address 0x{self.addr:02X} NACK · {e}")
        us = (time.perf_counter() - t) * 1e6
        return dict(dir="RX", kind="read", raw=[self.addr << 1, 0x00, (self.addr << 1) | 1, *d],
                    ok=True, metric=us, bytes=5, text=f"Read reg 0x00 → {fmt(d)}")

    def tx(self, text):
        b = parse_hex(text)
        self.port.write(b)
        return dict(dir="TX", kind="write", raw=[self.addr << 1, *b], ok=True, bytes=len(b) + 1,
                    text=f"Write to 0x{self.addr:02X} · {fmt(b)} · all ACK")

    def close(self):
        self.ctrl.close()


class SPI(Driver):
    rate = 20.0

    def open(self, cfg):
        from pyftdi.spi import SpiController
        self.ctrl = SpiController()
        self.ctrl.configure(cfg.get("url", "ftdi://ftdi:232h/1"))
        self.port = self.ctrl.get_port(cs=0, freq=float(cfg.get("clk", 10e6)), mode=int(cfg.get("mode", 0)))

    def poll(self):
        t = time.perf_counter()
        miso = list(self.port.exchange([0x9F, 0, 0, 0], duplex=True))  # JEDEC ID
        us = (time.perf_counter() - t) * 1e6
        return dict(dir="RX", kind="xfer", raw=[0x9F, 0, 0, 0], miso=miso, ok=True, metric=us, bytes=4,
                    text=f"JEDEC ID → {fmt(miso[1:])}")

    def tx(self, text):
        b = parse_hex(text)
        miso = list(self.port.exchange(b, duplex=True))
        return dict(dir="TX", kind="xfer", raw=b, miso=miso, ok=True, bytes=len(b),
                    text=f"Transfer {len(b)} B · MOSI {fmt(b)} · MISO {fmt(miso)}")

    def close(self):
        self.ctrl.close()


class EtherCAT(Driver):
    def open(self, cfg):
        import pysoem
        self.pysoem = pysoem
        self.m = pysoem.Master()
        self.m.open(cfg.get("ifname", "eth0"))
        self.n = self.m.config_init()
        if self.n <= 0:
            raise RuntimeError("no EtherCAT slaves found on this interface")
        self.m.config_map()
        self.m.state = pysoem.OP_STATE
        self.m.write_state()
        self.m.state_check(pysoem.OP_STATE, 50000)
        self.cycle = int(cfg.get("cycle", 1000))
        self.rate = min(1000.0, 1e6 / self.cycle)
        self.last = None

    def poll(self):
        t = time.perf_counter()
        self.m.send_processdata()
        wkc = self.m.receive_processdata(2000)
        exp = self.m.expected_wkc
        cyc = (t - self.last) * 1e6 if self.last else float(self.cycle)
        self.last = t
        raw = list(self.m.slaves[0].input[:8]) if self.m.slaves else []
        return dict(dir="RX", raw=raw, ok=(wkc == exp), metric=cyc, bytes=64,
                    text=f"Process data · {self.n} slaves · WKC {wkc}/{exp}")

    def tx(self, text):
        b = bytes(parse_hex(text))
        s = self.m.slaves[0]
        size = len(s.output)
        s.output = b.ljust(size, b"\0")[:size]
        return dict(dir="TX", raw=list(b), ok=True, text=f"Slave 1 output PDO ← {fmt(b)}")

    def close(self):
        self.m.state = self.pysoem.INIT_STATE
        self.m.write_state()
        self.m.close()


class TCP(Driver):
    rate = 5.0

    def open(self, cfg):
        self.query = cfg.get("query", "*IDN?")
        self.s = socket.create_connection((cfg.get("host", "127.0.0.1"), int(cfg.get("port", 5025))), timeout=2)
        self.s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def ask(self, q):
        q = q.strip()
        t = time.perf_counter()
        self.s.sendall((q + "\n").encode())
        reply = ""
        if q.endswith("?"):
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = self.s.recv(4096)
                if not chunk:
                    raise ConnectionError("socket closed by the instrument")
                buf += chunk
            reply = buf.decode(errors="replace").strip()
        return reply, (time.perf_counter() - t) * 1e3

    def poll(self):
        r, ms = self.ask(self.query)
        return dict(dir="RX", raw=list(self.query.encode()[:16]), ok=True, metric=ms,
                    bytes=len(self.query) + len(r) + 2, text=f"→ {self.query}  ← {r}")

    def tx(self, text):
        r, ms = self.ask(text)
        return dict(dir="TX", raw=list(text.encode()[:16]), ok=True, text=f"→ {text}" + (f"  ← {r}" if r else ""))

    def close(self):
        self.s.close()


class USB(Driver):
    rate = 20.0

    def open(self, cfg):
        import usb.core
        self.usb = usb
        vid, pid = int(cfg.get("vid", "0403"), 16), int(cfg.get("pid", "6014"), 16)
        self.dev = usb.core.find(idVendor=vid, idProduct=pid)
        if self.dev is None:
            raise RuntimeError(f"USB device {vid:04X}:{pid:04X} not found")
        try:
            self.dev.set_configuration()
        except usb.core.USBError:
            pass  # already configured
        self.ep = int(cfg.get("ep", "81"), 16)
        self.size = int(cfg.get("size", 512))

    def poll(self):
        t = time.perf_counter()
        try:
            d = self.dev.read(self.ep, self.size * 32, timeout=100)
        except self.usb.core.USBTimeoutError:
            return dict(dir="RX", raw=[], ok=True, metric=0.0, text=f"BULK IN EP 0x{self.ep:02X} · NAK (no data)")
        dt = time.perf_counter() - t
        return dict(dir="RX", raw=list(d[:8]), ok=True, metric=len(d) / dt / 1e6, bytes=len(d),
                    text=f"BULK IN EP 0x{self.ep:02X} · {len(d)} B · ACK")

    def tx(self, text):
        b = parse_hex(text)
        self.dev.write(0x02, b, timeout=200)
        return dict(dir="TX", raw=b, ok=True, text=f"BULK OUT EP 0x02 · {len(b)} B · ACK")


DRIVERS = {"i2c": I2C, "spi": SPI, "ethercat": EtherCAT, "tcp": TCP, "usb": USB}


class Bridge:
    def __init__(self):
        self.clients, self.drivers, self.tasks, self.paused = set(), {}, {}, False

    async def send(self, msg):
        data = json.dumps(msg)
        for ws in list(self.clients):
            try:
                await ws.send_str(data)
            except Exception:
                self.clients.discard(ws)

    async def stop(self, proto):
        task = self.tasks.pop(proto, None)
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        drv = self.drivers.pop(proto, None)
        if drv:
            try:
                await asyncio.to_thread(drv.locked, drv.close)
            except Exception:
                pass

    async def configure(self, proto, cfg):
        if proto not in DRIVERS:
            return
        await self.stop(proto)
        drv = DRIVERS[proto]()
        try:
            await asyncio.to_thread(drv.open, cfg)
        except Exception as e:
            await self.send(dict(type="caps", proto=proto, ok=False, msg=f"{type(e).__name__}: {e}"))
            return
        self.drivers[proto] = drv
        await self.send(dict(type="caps", proto=proto, ok=True, msg="connected"))
        self.tasks[proto] = asyncio.create_task(self.loop(proto, drv))

    async def loop(self, proto, drv):
        last_emit, polls = 0.0, 0
        while True:
            if self.paused:
                await asyncio.sleep(0.1)
                continue
            t = time.perf_counter()
            try:
                fr = await asyncio.to_thread(drv.locked, drv.poll)
            except Exception as e:
                fr = dict(dir="RX", raw=[], ok=False, text=f"{type(e).__name__}: {e}")
            polls += 1
            # forward at most ~10 frames/s to the browser, but always forward errors
            if t - last_emit >= 0.1 or not fr.get("ok", True):
                fr["bytes"] = fr.get("bytes", len(fr.get("raw", []))) * polls
                fr["count"] = polls
                polls, last_emit = 0, t
                await self.send(dict(type="frame", proto=proto, frame=fr))
            await asyncio.sleep(max(0.0, 1.0 / drv.rate - (time.perf_counter() - t)))


B = Bridge()


async def index(_):
    return web.FileResponse(PAGE)


async def ws_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    B.clients.add(ws)
    async for msg in ws:
        if msg.type != WSMsgType.TEXT:
            continue
        try:
            m = json.loads(msg.data)
        except ValueError:
            continue
        kind, proto = m.get("type"), m.get("proto")
        if kind == "config":
            asyncio.create_task(B.configure(proto, m.get("cfg", {})))
        elif kind == "tx":
            drv = B.drivers.get(proto)
            if not drv:
                await ws.send_str(json.dumps(dict(type="caps", proto=proto, ok=False, msg="not connected")))
                continue
            try:
                fr = await asyncio.to_thread(drv.locked, drv.tx, m.get("data", ""))
            except Exception as e:
                fr = dict(dir="TX", raw=[], ok=False, text=f"TX failed · {e}")
            await B.send(dict(type="frame", proto=proto, frame=fr))
        elif kind == "pause":
            B.paused = bool(m.get("on"))
    B.clients.discard(ws)
    return ws


def main():
    ap = argparse.ArgumentParser(description="Interface Bench hardware bridge (Built by Nova Agentic)")
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    if not PAGE.exists():
        raise SystemExit(f"Put index.html next to bridge.py ({PAGE} not found).")
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/ws", ws_handler)
    print(f"Interface Bench bridge running. Open http://localhost:{args.port} and press Hardware.")
    web.run_app(app, host="127.0.0.1", port=args.port, print=None)


if __name__ == "__main__":
    main()
