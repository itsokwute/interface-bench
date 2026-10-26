# Interface Bench

Multi-protocol interface dashboard for **EtherCAT, TCP/IP, USB, I²C and SPI**.

- Simulated mode: live traffic, I²C/SPI timing diagrams, jitter/latency charts, decoded frame log, fault injection, CSV copy.
- Hardware mode: `bridge.py` streams real bus traffic from your PC (FT232H for I²C/SPI, pysoem for EtherCAT, pyusb for USB, sockets for TCP/IP).

## Run hardware mode

Step 1, open Command Prompt in this folder.
Step 2, type `pip install aiohttp pyftdi pysoem pyusb` and press Enter.
Step 3, type `python bridge.py` and press Enter.
Step 4, open your browser and type `http://localhost:8765`.
Step 5, click **Hardware**.

Built by Nova Agentic
