import argparse
import requests
import ssl
import socket
import logging
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='Detects potentially insecure TLS configurations on a target website or server.')
    parser.add_argument('target', help='The target website or server (e.g., https://example.com or example.com).')
    parser.add_argument('--port', type=int, default=443, help='The port to connect to (default: 443).')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout for connection attempts (default: 10 seconds).')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output for debugging.')
    return parser

def get_ssl_context():
    """
    Creates an SSL context with default settings.  Can be modified to enforce minimum TLS versions.
    """
    context = ssl.create_default_context()
    # Example: Enforce TLS 1.2 or higher (Uncomment to enforce)
    # context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context

def check_weak_ciphers(hostname, port, timeout=10):
    """
    Checks for weak ciphers supported by the target.  This function requires OpenSSL and cryptography libraries.
    """
    try:
        context = SSL.Context(SSL.TLSv1_2_METHOD) # Or another appropriate method
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        conn = SSL.Connection(context, sock)
        conn.connect((hostname, port))

        try:
            conn.do_handshake()
        except SSL.Error as e:
            logging.error(f"SSL Handshake failed: {e}")
            return []


        cipher = conn.get_cipher_name()
        logging.info(f"Cipher used: {cipher}")


        weak_ciphers = [
            "DES-CBC3-SHA",  # Triple DES
            "RC4-SHA",       # RC4
            "EXP-EDH-RSA-DES-CBC-SHA", # Export grade
            "EXP-EDH-DSS-DES-CBC-SHA", # Export grade
            "EXP-DES-CBC-SHA",  # Export grade
            "DES-CBC-SHA", # Single DES
        ]

        if cipher in weak_ciphers:
           logging.warning(f"Weak cipher detected: {cipher}")
           return [cipher]


        conn.shutdown()
        conn.close()
        return []

    except socket.timeout:
        logging.error(f"Connection timeout to {hostname}:{port}")
        return []
    except socket.gaierror as e:
         logging.error(f"Invalid hostname: {hostname}.  Error: {e}")
         return []
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return []


def get_certificate_info(hostname, port, timeout=10):
    """
    Retrieves and analyzes the SSL certificate information.
    """
    try:
        context = get_ssl_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                if not cert:
                    logging.warning("No certificate found.")
                    return {}

                x509_cert = x509.load_der_certificate(cert, default_backend())
                issuer = x509_cert.issuer.rfc4514_string()
                subject = x509_cert.subject.rfc4514_string()
                not_valid_before = x509_cert.not_valid_before
                not_valid_after = x509_cert.not_valid_after

                return {
                    "issuer": issuer,
                    "subject": subject,
                    "not_valid_before": not_valid_before,
                    "not_valid_after": not_valid_after
                }

    except socket.timeout:
        logging.error(f"Connection timeout to {hostname}:{port}")
        return {}
    except socket.gaierror as e:
         logging.error(f"Invalid hostname: {hostname}.  Error: {e}")
         return {}
    except ssl.SSLError as e:
        logging.error(f"SSL Error: {e}")
        return {}
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return {}

def check_tls_version(hostname, port, timeout=10):
    """
    Checks the supported TLS versions.

    Returns:
        A list of supported TLS versions (e.g., ['TLSv1.2', 'TLSv1.3']).
    """
    supported_versions = []
    try:
        for version in [ssl.TLSVersion.TLSv1_0, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
            try:
                context = ssl.create_default_context()
                context.minimum_version = version

                with socket.create_connection((hostname, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocol = ssock.version()
                        supported_versions.append(protocol)
                        logging.info(f"Supported TLS version: {protocol}")
            except ssl.SSLError as e:
                # Expected for versions that are not supported
                pass
            except Exception as e:
                logging.error(f"Error checking TLS version {version}: {e}")

    except socket.gaierror as e:
         logging.error(f"Invalid hostname.  Error: {e}")
         return []

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

    return supported_versions


def main():
    """
    Main function to orchestrate the TLS security checks.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    target = args.target
    port = args.port
    timeout = args.timeout

    # Validate target URL
    try:
        parsed_url = urlparse(target)
        if not parsed_url.netloc: # Handles cases where only the path is provided.
            target_hostname = target  #Treat target as only hostname
        else:
            target_hostname = parsed_url.netloc
    except Exception as e:
        logging.error(f"Invalid target URL: {e}")
        sys.exit(1)



    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    logging.info(f"Starting TLS security scan for {target_hostname}:{port}")

    # 1. Check certificate information
    cert_info = get_certificate_info(target_hostname, port, timeout)
    if cert_info:
        logging.info("Certificate Information:")
        for key, value in cert_info.items():
            logging.info(f"  {key}: {value}")
    else:
        logging.warning("Could not retrieve certificate information.")

    # 2. Check for weak ciphers
    weak_ciphers_found = check_weak_ciphers(target_hostname, port, timeout)
    if weak_ciphers_found:
      logging.warning(f"Potentially weak ciphers detected: {weak_ciphers_found}")
    else:
      logging.info("No weak ciphers detected.")



    # 3. Check supported TLS versions
    supported_versions = check_tls_version(target_hostname, port, timeout)
    if supported_versions:
        logging.info(f"Supported TLS versions: {supported_versions}")
        if "TLSv1.0" in supported_versions or "TLSv1.1" in supported_versions:
            logging.warning("TLS 1.0 or TLS 1.1 is enabled.  These versions are considered insecure.")
    else:
        logging.warning("Could not determine supported TLS versions.")

    logging.info(f"TLS security scan completed for {target_hostname}:{port}")


if __name__ == "__main__":
    main()