import socket
import ssl


def get_cert_info(hostname: str, port: int = 443, timeout: int = 5) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                cert = ss.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"verified": False, "error": str(e), "issuer": None}
    except (OSError, ssl.SSLError) as e:
        return {"verified": None, "error": str(e), "issuer": None}
    issuer = {}
    for rdn in cert.get("issuer", ()):
        for k, v in rdn:
            issuer[k] = v
    return {"verified": True, "error": None,
            "issuer": issuer.get("organizationName") or issuer.get("commonName")}
