from __future__ import annotations

import asyncio
import aioftp


import ssl


def create_ssl_context():
    # Create a context for server-side sockets
    ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)

    # Load server certificate and private key
    ctx.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # Optional: require and verify client certificates (mutual TLS)
    # ctx.verify_mode = ssl.CERT_REQUIRED
    # ctx.load_verify_locations(cafile="ca_clients.pem")

    # Enforce TLS versions and strong ciphers
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE+AESGCM:!aNULL:!eNULL:!LOW:!3DES:!MD5")

    # Disable insecure legacy options (mostly set by create_default_context already)
    ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_COMPRESSION


async def main():
    users = [
        aioftp.User(
            "senyai",
            "lol",
            base_path="ftp_root",
            permissions=(
                aioftp.Permission("/", readable=False, writable=False),
                aioftp.Permission("/a", readable=True, writable=False),
            ),
        )
    ]

    server = aioftp.Server(users, ssl=create_ssl_context())
    await server.run(host="127.0.0.1", port=8025)
    print("done!")


asyncio.run(main())
