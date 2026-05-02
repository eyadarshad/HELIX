"""
cert_verifier.py — Windows Authenticode Certificate Chain Verification

Uses PowerShell's Get-AuthenticodeSignature to do a REAL chain validation,
not just "does the signature field exist". This verifies:
  1. The cryptographic signature is valid (not tampered)
  2. The certificate chain leads to a trusted Root CA
  3. The certificate has NOT been revoked

Contrast with the naive approach (checking PE optional header or
Authenticode structure existence) which some malware defeats by:
  - Copying an expired cert from a legitimate file
  - Using a self-signed cert (not from a Root CA)
  - Padding an invalid signature blob into the PE security directory

Result dict:
  {
    "is_signed":      0 or 1,   # any signature present (even invalid)
    "signer_trusted": 0 or 1,   # chain valid + Root CA trusted
    "signer_name":    str,       # "CN=Microsoft Corporation, ..." or ""
    "cert_status":    str,       # "Valid" | "NotSigned" | "UnknownError" | ...
  }
"""
from __future__ import annotations

import json
import subprocess
import os

# Cache results for the same filepath to avoid repeat PowerShell calls
_CACHE: dict[str, dict] = {}


def verify_signature(filepath: str) -> dict:
    """
    Verify the Authenticode signature of a PE file using PowerShell.

    Returns a dict with keys: is_signed, signer_trusted, signer_name, cert_status.
    Always returns safe defaults on error (is_signed=0, signer_trusted=0).
    """
    if filepath in _CACHE:
        return _CACHE[filepath]

    result = _DEFAULT.copy()

    try:
        ps_script = (
            f"$sig = Get-AuthenticodeSignature '{filepath}'; "
            "$out = @{"
            " Status=$sig.Status.ToString(); "
            " Subject=if($sig.SignerCertificate){{$sig.SignerCertificate.Subject}}else{{''}}; "
            " IsSigned=if($sig.SignerCertificate){{1}}else{{0}} "
            "}; "
            "ConvertTo-Json $out -Compress"
        )

        # CREATE_NO_WINDOW prevents a CMD flash when running PowerShell
        import subprocess as _sp
        si = _sp.STARTUPINFO()
        si.dwFlags |= _sp.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE

        proc = _sp.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=8,
            creationflags=0x08000000,  # CREATE_NO_WINDOW
            startupinfo=si,
        )

        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout.strip())
            status       = data.get("Status", "NotSigned")
            subject      = data.get("Subject", "")
            has_cert     = int(data.get("IsSigned", 0))

            result["cert_status"]    = status
            result["is_signed"]      = has_cert
            result["signer_name"]    = subject
            # Only mark trusted if PowerShell confirms the FULL chain is valid
            result["signer_trusted"] = 1 if status == "Valid" else 0

    except Exception:
        pass  # Return safe defaults on any error

    _CACHE[filepath] = result
    return result


_DEFAULT = {
    "is_signed":      0,
    "signer_trusted": 0,
    "signer_name":    "",
    "cert_status":    "Unknown",
}
