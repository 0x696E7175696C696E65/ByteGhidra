"""
Generate + Install TLS Certificates for the Private Server
===========================================================
CONFIRMED via binary RE:
  - Game uses libcurl (statically linked) with the Windows SChannel TLS backend
  - SChannel cert validation reads from the Windows certificate store
    (CRYPT32.DLL::CertEnumCertificatesInStore — confirmed in FUN_7ff7115f5850)
  - Therefore: install self-signed cert to Windows Trusted Root = game trusts it
  - No game modification, no DLL injection, no cert pinning to bypass

This script:
  1. Generates a self-signed cert covering all Bungie domains
  2. Installs it to the Windows Trusted Root store via certutil
  3. Requires Administrator for step 2

Run once before starting the private server.
"""

import subprocess
import os
import sys

CERT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")

def install_cert(cert_path):
    print("")
    print("Installing certificate to Windows Trusted Root store...")
    print("(Required: libcurl+SChannel reads from Windows cert store via CRYPT32)")
    try:
        subprocess.run([
            "certutil", "-addstore", "-f", "ROOT", cert_path
        ], check=True)
        print("[+] Certificate installed to Trusted Root store")
    except subprocess.CalledProcessError:
        print("[!] certutil failed — run as Administrator to install certificate")
        print("    Manual: certmgr.msc → Trusted Root → Import → {}".format(cert_path))

def generate_certs():
    os.makedirs(CERT_DIR, exist_ok=True)

    cert_path = os.path.join(CERT_DIR, "server.crt")
    key_path  = os.path.join(CERT_DIR, "server.key")

    if os.path.exists(cert_path):
        print("[i] Certificates already exist at {}".format(CERT_DIR))
        install_cert(cert_path)
        return

    print("Generating self-signed certificate...")
    print("SANs: platform.bungie.net, www.bungie.net, *.bungie.net")
    print("")

    # Generate using OpenSSL
    san_config = """[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req

[dn]
C=US
ST=Washington
L=Bellevue
O=Bungie Inc
CN=platform.bungie.net

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[alt_names]
DNS.1 = platform.bungie.net
DNS.2 = www.bungie.net
DNS.3 = oauth.bungie.net
DNS.4 = stats.bungie.net
DNS.5 = *.bungie.net
DNS.6 = localhost
DNS.7 = signon2.gravityshavings.net
DNS.8 = www1.signon2.gravityshavings.net
DNS.9 = www2.signon2.gravityshavings.net
IP.1  = 127.0.0.1
"""

    config_path = os.path.join(CERT_DIR, "openssl.cnf")
    with open(config_path, "w") as f:
        f.write(san_config)

    try:
        subprocess.run([
            "openssl", "req", "-x509", "-nodes",
            "-newkey", "rsa:2048",
            "-keyout", key_path,
            "-out",    cert_path,
            "-days",   "3650",
            "-config", config_path,
        ], check=True, capture_output=True)
        print("[+] Certificate: {}".format(cert_path))
        print("[+] Key:         {}".format(key_path))
    except FileNotFoundError:
        print("[!] OpenSSL not found. Install OpenSSL or use mitmproxy.")
        print("    Windows: winget install OpenSSL.Light")
        return
    except subprocess.CalledProcessError as e:
        print("[!] OpenSSL failed: {}".format(e.stderr.decode()))
        return

    # Install to Windows certificate store
    install_cert(cert_path)

    print("")
    print("Done! Start the server with: python server.py --tier1")
    print("")
    print("ALTERNATIVE: Use mitmproxy CA (no cert installation needed)")
    print("  pip install mitmproxy")
    print("  mitmproxy --mode transparent --ssl-insecure")
    print("  Then configure system proxy to 127.0.0.1:8080")


if __name__ == "__main__":
    generate_certs()
