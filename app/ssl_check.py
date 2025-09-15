"""
ssl_check.py

Basic SSL and domain validation module for phishing detection.

Public function:
    check_ssl(domain: str) -> dict

Requires:
    pip install cryptography python-whois
"""

import socket
import ssl
import datetime
import whois
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def _get_certificate(domain: str, port: int = 443, timeout: int = 5):
    """Fetch the server's SSL certificate (PEM bytes)."""
    ctx = ssl.create_default_context()
    conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.settimeout(timeout)
    try:
        conn.connect((domain, port))
        der_cert = conn.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        conn.close()
        return pem_cert
    except Exception as e:
        return None


def _parse_certificate(pem_cert: str):
    """Parse PEM certificate using cryptography."""
    cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
    return cert


def _get_domain_age(domain: str):
    """Return domain age in days using WHOIS (may fail if registrar blocks)."""
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):  # sometimes it's a list
            creation_date = creation_date[0]
        if not creation_date:
            return None
        today = datetime.datetime.utcnow()
        age_days = (today - creation_date).days
        return age_days
    except Exception:
        return None


def check_ssl(domain: str) -> dict:
    """
    Check SSL certificate validity and domain info.

    Returns dict:
    {
      "domain": "example.com",
      "ssl": {
         "cert_valid": True,
         "expiry_days": 120,
         "expired": False,
         "self_signed": False,
         "cn_mismatch": False
      },
      "domain_age_days": 5230,
      "final_verdict": "Likely Safe"
    }
    """
    results = {
        "domain": domain,
        "ssl": {},
        "domain_age_days": None,
        "final_verdict": "Unknown"
    }

    # Get certificate
    pem_cert = _get_certificate(domain)
    if not pem_cert:
        results["ssl"]["cert_valid"] = False
        results["ssl"]["explanation"] = "Unable to retrieve certificate"
        results["final_verdict"] = "Suspicious — No certificate"
        return results

    try:
        cert = _parse_certificate(pem_cert)
    except Exception as e:
        results["ssl"]["cert_valid"] = False
        results["ssl"]["explanation"] = f"Certificate parse error: {e}"
        results["final_verdict"] = "Suspicious — Bad certificate"
        return results

    # Expiry check
    not_after = cert.not_valid_after
    days_left = (not_after - datetime.datetime.utcnow()).days
    expired = days_left < 0
    results["ssl"]["expiry_days"] = days_left
    results["ssl"]["expired"] = expired

    # Self-signed check: issuer == subject
    self_signed = cert.issuer == cert.subject
    results["ssl"]["self_signed"] = self_signed

    # CN mismatch check
    try:
        cn = None
        for attr in cert.subject:
            if attr.oid.dotted_string == "2.5.4.3":  # Common Name
                cn = attr.value
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        alt_names = san.value.get_values_for_type(x509.DNSName)
    except Exception:
        cn, alt_names = None, []

    cn_mismatch = False
    if cn and domain not in cn and all(domain not in alt for alt in alt_names):
        cn_mismatch = True
    results["ssl"]["cn_mismatch"] = cn_mismatch

    # Domain age
    age_days = _get_domain_age(domain)
    results["domain_age_days"] = age_days

    # Final verdict
    if expired or self_signed or cn_mismatch or (age_days is not None and age_days < 180):
        results["final_verdict"] = "Suspicious"
    else:
        results["final_verdict"] = "Likely Safe"

    return results


# Quick test harness
if __name__ == "__main__":
    test_domains = [
        "google.com",
        "expired.badssl.com",
        "self-signed.badssl.com",
    ]
    for d in test_domains:
        print("=" * 80)
        print("Domain:", d)
        res = check_ssl(d)
        print(res)
