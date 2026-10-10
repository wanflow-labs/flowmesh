#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Byte-for-byte TCP forwarder (lab only), e.g. to put the control server behind a high port.
Usage: tcp_forward.py LISTEN_HOST LISTEN_PORT TARGET_HOST TARGET_PORT"""
import asyncio
import sys


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    finally:
        writer.close()


async def handle(cr, cw, target):
    print(f"connection from {cw.get_extra_info('peername')}", flush=True)
    tr, tw = await asyncio.open_connection(*target)
    await asyncio.gather(pipe(cr, tw), pipe(tr, cw), return_exceptions=True)


async def main():
    lh, lp, th, tp = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
    server = await asyncio.start_server(lambda r, w: handle(r, w, (th, tp)), lh, lp)
    async with server:
        await server.serve_forever()


asyncio.run(main())
