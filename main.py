import argparse
import ipaddress
import ssl
import socket
import logging
from datetime import datetime, timezone
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

WEAK_CIPHERS = [
    "DES-CBC3-SHA",  # Triple DES
    "RC4-SHA",       # RC4
    "EXP-EDH-RSA-DES-CBC-SHA",  # Export grade
    "EXP-EDH-DSS-DES-CBC-SHA",  # Export grade
    "EXP-DES-CBC-SHA",  # Export grade
    "DES-CBC-SHA",   # Single DES
]

def setup_argparse():
    parser = argparse.ArgumentParser(description='Detects potentially insecure TLS configurations on a target website or server.')
    parser.add_argument('target', help='The target website or server (e.g., https://example.com or example.com).')
    parser.add_argument('--port', type=int, default=443, help='The port to connect to (default: 443). A port written in a URL target takes precedence.')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for connection attempts (default: 10 seconds).')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output for debugging.')
    return parser

def _is_self_signed(x509_cert, issuer, subject):
    """True only when the certificate was signed with its own key.

    Uses signature verification (verify_directly_issued_by, cryptography
    42 and newer) when available: a certificate whose issuer string
    merely equals its subject string, such as a CA issued leaf that
    shares the CA name, is not self signed. On older cryptography
    versions without that method, falls back to issuer and subject
    string equality.
    """
    verify = getattr(x509_cert, "verify_directly_issued_by", None)
    if callable(verify):
        try:
            verify(x509_cert)
            return True
        except Exception:
            return False
    return issuer == subject


def _as_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

def get_certificate_info(hostname, port, timeout=10):
    """Retrieve certificate information with a non-verifying context.

    Verification is turned off on purpose: this tool exists to inspect
    certificates that fail verification (self signed, expired, or issued
    for another host), so it fetches the certificate first and reports
    those conditions as findings. Returns a dict, or None when no
    connection could be made at all.
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                # With verification switched off above, this call returns an empty dictionary on most builds, so the SAN and CN lookups below that read from cert_dict usually find nothing. The cryptography based fallback further down is not a belt and braces extra; on an unverified connection it is the path that actually produces the name list.
                cert_dict = ssock.getpeercert()
                if not cert_bin:
                    logging.warning("No certificate found.")
                    return {}

                x509_cert = x509.load_der_certificate(cert_bin, default_backend())
                issuer = x509_cert.issuer.rfc4514_string()
                subject = x509_cert.subject.rfc4514_string()
                try:
                    not_valid_before = x509_cert.not_valid_before_utc
                    not_valid_after = x509_cert.not_valid_after_utc
                except AttributeError:
                    not_valid_before = x509_cert.not_valid_before
                    not_valid_after = x509_cert.not_valid_after

                now = datetime.now(timezone.utc)
                nb = _as_utc(not_valid_before)
                na = _as_utc(not_valid_after)

                # Hostname check against SAN entries (and CN as fallback).
                names = []
                for kind, value in cert_dict.get("subjectAltName", ()):
                    if kind in ("DNS", "IP Address"):
                        names.append(value)
                if not names:
                    try:
                        san = x509_cert.extensions.get_extension_for_class(
                            x509.SubjectAlternativeName).value
                        for cls in (getattr(x509, "IPAddress", None), getattr(x509, "DNSName", None)):
                            if cls is not None:
                                names.extend(str(v) for v in san.get_values_for_type(cls))
                    except Exception:
                        pass
                if not names:
                    for rdn in cert_dict.get("subject", ()):
                        for key, value in rdn:
                            if key == "commonName":
                                names.append(value)
                if not names:
                    for part in subject.replace(" = ", "=").split(","):
                        part = part.strip()
                        if part.startswith("CN="):
                            names.append(part[3:].strip())
                hostname_mismatch = True
                try:
                    ip = ipaddress.ip_address(hostname)
                    hostname_mismatch = not any(
                        (lambda v: v == ip)(_try_ip(n)) for n in names)
                except ValueError:
                    hn = hostname.lower().rstrip(".")
                    for n in names:
                        nl = n.lower()
                        if nl == hn or (nl.startswith("*.") and hn.endswith(nl[1:]) and hn.count(".") == nl.count(".")):
                            hostname_mismatch = False

                return {
                    "issuer": issuer,
                    "subject": subject,
                    "not_valid_before": not_valid_before,
                    "not_valid_after": not_valid_after,
                    "self_signed": _is_self_signed(x509_cert, issuer, subject),
                    "expired": (na is not None and na < now),
                    "not_yet_valid": (nb is not None and nb > now),
                    "hostname_mismatch": hostname_mismatch,
                }

    except socket.timeout:
        logging.error(f"Connection timeout to {hostname}:{port}")
        return None
    except socket.gaierror as e:
        logging.error(f"Invalid hostname: {hostname}.  Error: {e}")
        return None
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return None

def _try_ip(name):
    try:
        return ipaddress.ip_address(name)
    except ValueError:
        return None

def check_weak_ciphers(hostname, port, timeout=10):
    """Offer each weak cipher suite in turn and record which handshakes succeed.

    Returns (found, completed): found lists the weak suites the server
    accepted; completed counts handshake attempts that reached a TLS
    answer (success or a TLS level refusal). A connection error counts
    as not completed, so an unreachable target is never reported clean.
    The connection is closed on every path.
    """
    # Each suite is offered under TLS 1.2, then TLS 1.1, then TLS 1.0
    # shaped contexts, because several suites in the list were only ever
    # negotiable under older protocol versions. The list itself covers
    # the six named suites below; a weak suite outside the list is not
    # tested.
    methods = [m for m in (getattr(SSL, "TLSv1_2_METHOD", None),
                           getattr(SSL, "TLSv1_1_METHOD", None),
                           getattr(SSL, "TLSv1_METHOD", None)) if m is not None]
    found = []
    completed = 0
    for suite in WEAK_CIPHERS:
        suite_completed = False
        for method in methods:
            conn = None
            sock = None
            try:
                context = SSL.Context(method)
                try:
                    context.set_cipher_list(suite.encode())
                except Exception:
                    # The local TLS library does not know this suite name
                    # at all; no method context can test it, so skip the
                    # suite entirely.
                    break
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                conn = SSL.Connection(context, sock)
                conn.connect((hostname, port))
                try:
                    conn.do_handshake()
                except SSL.Error:
                    suite_completed = True
                    continue
                suite_completed = True
                name = conn.get_cipher_name()
                logging.warning(f"Weak cipher accepted by server: {name or suite}")
                found.append(name or suite)
                break
            except (socket.timeout, socket.gaierror, OSError) as e:
                logging.error(f"Weak cipher check could not reach {hostname}:{port}: {e}")
                break
            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")
                break
            finally:
                if conn is not None:
                    try:
                        conn.shutdown()
                    except Exception:
                        pass
                    try:
                        conn.close()
                    except Exception:
                        pass
                elif sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
        if suite_completed:
            completed += 1
    return found, completed

def check_tls_version(hostname, port, timeout=10):
    """Probe each TLS version with minimum and maximum pinned to that
    one version, so acceptance of each version is tested on its own.

    Member names verified on this interpreter (Python 3.12):
    TLSv1, TLSv1_1, TLSv1_2, TLSv1_3 exist; TLSv1_0 does not.
    Returns (supported, completed): completed counts probes that got a
    TLS level answer (a handshake success or refusal). Connection
    errors count as not completed.
    """
    probes = [
        (ssl.TLSVersion.TLSv1, "TLSv1.0"),
        (ssl.TLSVersion.TLSv1_1, "TLSv1.1"),
        (ssl.TLSVersion.TLSv1_2, "TLSv1.2"),
        (ssl.TLSVersion.TLSv1_3, "TLSv1.3"),
    ]
    supported = []
    completed = 0
    for version, label in probes:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = version
            context.maximum_version = version
            if version != ssl.TLSVersion.TLSv1_3:
                try:
                    context.set_ciphers("DEFAULT@SECLEVEL=0")
                except ssl.SSLError:
                    pass
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    protocol = ssock.version()
                    completed += 1
                    if protocol and protocol not in supported:
                        supported.append(protocol)
                    logging.info(f"Supported TLS version: {protocol}")
        except ssl.SSLError:
            completed += 1
        except Exception as e:
            logging.error(f"Error checking TLS version {label}: {e}")
    return supported, completed


def main():
    parser = setup_argparse()
    args = parser.parse_args()

    target = args.target
    timeout = args.timeout

    parsed_url = urlparse(target)
    if parsed_url.netloc:
        target_hostname = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else args.port
        if not target_hostname:
            logging.error(f"Invalid target URL: {target}")
            sys.exit(1)
    else:
        # Bare target without a scheme: keep only the host (and an
        # explicit port when written as host:port); a path or query
        # suffix such as example.com/login is not part of the hostname.
        hostport = target.split("/")[0].split("?")[0].split("#")[0]
        if hostport.startswith("[") and "]" in hostport:
            target_hostname = hostport[1:hostport.index("]")]
            rest = hostport[hostport.index("]") + 1:]
            port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else args.port
        elif hostport.count(":") == 1 and hostport.rsplit(":", 1)[1].isdigit():
            target_hostname, port_text = hostport.rsplit(":", 1)
            port = int(port_text)
        else:
            target_hostname = hostport
            port = args.port
        if not target_hostname:
            logging.error(f"Invalid target: {target}")
            sys.exit(1)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    logging.info(f"Starting TLS security scan for {target_hostname}:{port}")

    checks_completed = 0

    # 1. Check certificate information
    cert_info = get_certificate_info(target_hostname, port, timeout)
    if cert_info:
        checks_completed += 1
        logging.info("Certificate Information:")
        for key, value in cert_info.items():
            logging.info(f"  {key}: {value}")
        if cert_info.get("self_signed"):
            logging.warning("Certificate is self signed (issuer matches subject).")
        if cert_info.get("expired"):
            logging.warning("Certificate is expired.")
        if cert_info.get("not_yet_valid"):
            logging.warning("Certificate is not yet valid.")
        if cert_info.get("hostname_mismatch"):
            logging.warning(f"Certificate does not match hostname {target_hostname}.")
    elif cert_info is None:
        logging.warning("Could not retrieve certificate information.")
    else:
        logging.warning("No certificate was presented.")

    # 2. Check for weak ciphers
    weak_ciphers_found, cipher_completed = check_weak_ciphers(target_hostname, port, timeout)
    if cipher_completed:
        checks_completed += 1
        if weak_ciphers_found:
            logging.warning(f"Potentially weak ciphers detected: {weak_ciphers_found}")
        else:
            logging.info("No weak ciphers detected.")
    else:
        logging.error("Weak cipher check could not be performed: no handshake reached a TLS answer.")

    # 3. Check supported TLS versions
    supported_versions, version_completed = check_tls_version(target_hostname, port, timeout)
    if version_completed:
        checks_completed += 1
    if supported_versions:
        logging.info(f"Supported TLS versions: {supported_versions}")
        if "TLSv1.0" in supported_versions or "TLSv1.1" in supported_versions:
            logging.warning("TLS 1.0 or TLS 1.1 is enabled.  These versions are considered insecure.")
    else:
        logging.warning("Could not determine supported TLS versions.")

    if checks_completed == 0:
        logging.error(f"TLS security scan failed for {target_hostname}:{port}: no check could be performed.")
        sys.exit(1)

    logging.info(f"TLS security scan completed for {target_hostname}:{port}")


if __name__ == "__main__":
    main()
