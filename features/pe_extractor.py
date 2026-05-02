"""
pe_extractor.py — Static PE File Feature Engine (22 features)

Extracts features directly from the PE file header, import table,
and section table WITHOUT executing the file.

Why this works better than instruction-level features:
    Malware MUST import dangerous Windows API functions in order to:
    - Inject into other processes (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
    - Evade debuggers (IsDebuggerPresent, CheckRemoteDebuggerPresent)
    - Establish persistence (RegSetValueEx, CreateService)
    - Download payloads (URLDownloadToFile, InternetOpen, WinExec)

    Benign programs (notepad.exe, calc.exe, git.exe) never need these.
    This is the primary signal used by real AV static engines.

Features (22 total):
    Import-based (most discriminative):
        1.  suspicious_import_count    — total count of dangerous API imports
        2.  has_injection_imports      — 1 if process-injection APIs present
        3.  has_evasion_imports        — 1 if anti-debug APIs present
        4.  has_network_imports        — 1 if download/connect APIs present
        5.  has_persistence_imports    — 1 if registry/service APIs present
        6.  import_count               — total imports (0 = stripped = suspicious)
        7.  get_proc_address_present   — 1 if GetProcAddress used (runtime import hiding)
        8.  load_library_present       — 1 if LoadLibrary used (runtime DLL loading)

    Section-based (packed/encrypted detection):
        9.  max_section_entropy        — highest section entropy (>=7.2 = packed)
        10. avg_section_entropy        — average entropy across sections
        11. n_sections                 — section count (very few = stripped, many = stuffed)
        12. has_unusual_section_name   — non-standard section names (.upx, .themida, etc.)
        13. rx_rw_section              — executable+writable section (shellcode injection)
        14. entry_outside_text         — entry point not in .text section

    PE Header anomalies:
        15. timestamp_anomaly          — 0 or year > 2030 (malware often zeroes this)
        16. checksum_mismatch          — PE checksum field = 0 (legitimate tools always set it)
        17. has_tls                    — TLS callbacks present (anti-analysis technique)
        18. is_dll                     — 1 if file is DLL (malware droppers often hide as DLLs)
        19. overlay_present            — data appended after last section (packer signature)

    String-based:
        20. url_count                  — count of http:// or https:// strings in data
        21. suspicious_string_count    — cmd.exe, powershell, regsvr32, mshta, wscript etc.
        22. ip_pattern_count           — IPv4 address strings (C2 server indicators)
"""

from __future__ import annotations
import re
import math
import struct
import datetime

try:
    import pefile
    _PEFILE_OK = True
except ImportError:
    _PEFILE_OK = False

# ── Dangerous API lists (precision-tuned to avoid FP on benign Windows apps) ─

# Process injection — ONLY cross-process variants (not VirtualAlloc/VirtualProtect which .NET/CRT use)
INJECTION_APIS = {
    "virtualallocex",          # allocate in ANOTHER process — only malware does this
    "writeprocessmemory",      # write to another process — only debuggers / malware
    "createremotethread",      # create thread in another process
    "createremotethreadex",
    "ntcreatethreadex",        # native API equivalents
    "rtlcreateuserthread",
    "queueuserapc",            # APC injection
    "ntmapviewofsection",      # section injection
    "ntwritevirtualmemory",    # native write-to-process
    "ntallocatevirtualmemory", # native version — used by loaders/malware
}

# Anti-debugging — specific to evasion, not general-purpose
EVASION_APIS = {
    "checkremotedebuggerpresent",  # more specific than IsDebuggerPresent
    "ntqueryinformationprocess",
    "zwqueryinformationprocess",
    "ntsetinformationthread",     # hides thread from debugger
    "zwsetinformationthread",
    "debugactiveprocess",
    "ntcreatedebugobject",
}

# Download / remote execution
NETWORK_APIS = {
    "urldownloadtofilew",      # download file from URL
    "urldownloadtofilea",
    "internetopena",           # WinInet HTTP open
    "internetopenw",
    "wsastartup",              # raw socket initialisation
    "winexec",                 # execute arbitrary process
    "shellexecuteexa",         # execute with elevated/hidden window
    "shellexecuteexw",
    "downloadfile",            # BITS
    "bitsstartdownload",
}

# Persistence — registry WRITE and service creation
PERSISTENCE_APIS = {
    "regsetvalueexa",
    "regsetvalueexw",
    "regcreatekeyexa",
    "regcreatekeyexw",
    "createservicea",
    "createservicew",
    "openscmanagera",
    "openscmanagerw",
}

RUNTIME_IMPORT_APIS = {
    "getprocaddress",        # resolve import at runtime (hides real API usage)
}

UNUSUAL_SECTIONS = {
    ".upx0", ".upx1", ".upx2", ".themida", ".vmprotect",
    "pec2",  ".aspack", ".adata", "nsp0", "nsp1",
}

SUSPICIOUS_STRINGS = [
    # Very specific malware-only patterns (reduced to avoid false positives on complex apps)
    b"net user /add",          # account creation — never in legit apps
    b"net localgroup administrators",  # privilege escalation
    b"ransom", b"bitcoin",     b"wallet.dat",  # ransomware indicators
    b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",  # persistence
    b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",             # hijack
    b"reflective", b"shellcode",       # technical malware terms — not in legit code
    b"mimikatz",   b"lsass.exe",       # credential dumping references
]

PE_FEATURE_NAMES = [
    # Import-based
    "suspicious_import_count",
    "has_injection_imports",
    "has_evasion_imports",
    "has_network_imports",
    "has_persistence_imports",
    "import_count",
    "n_imported_dlls",         # NEW: unique DLL count (malware: few stealthy DLLs; legit: many)

    # Section-based
    "max_section_entropy",
    "avg_section_entropy",
    "n_sections",
    "has_unusual_section_name",
    "rx_rw_section",
    "entry_outside_text",

    # PE Header
    "timestamp_anomaly",
    "checksum_mismatch",
    "has_tls",
    "is_dll",
    "overlay_present",
    "is_signed",               # digital signature present: Chrome/VS Code = 1, malware = 0
    "has_version_info",        # NEW: VERSIONINFO resource — legit apps always have it
    "has_manifest",            # NEW: XML application manifest — legit apps always have it

    # String-based
    "url_count",
    "suspicious_string_count",
    "ip_pattern_count",
]


def _section_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string, scaled 0–8."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n   = len(data)
    ent = 0.0
    for f in freq:
        if f:
            p    = f / n
            ent -= p * math.log2(p)
    return round(ent, 4)


def extract_pe_features(filepath: str) -> dict:
    """
    Parse a PE file and return 22 static features.
    Returns all-zero dict if pefile unavailable or file is not a valid PE.
    """
    zeros = {f: 0.0 for f in PE_FEATURE_NAMES}

    if not _PEFILE_OK:
        return zeros

    try:
        pe = pefile.PE(filepath, fast_load=False)
    except Exception:
        return zeros

    feats = dict(zeros)

    # ── Raw file bytes (for string scan) ─────────────────────────────────────
    try:
        with open(filepath, "rb") as fh:
            raw_bytes = fh.read()
    except Exception:
        raw_bytes = b""

    # ── Import analysis ───────────────────────────────────────────────────────
    injection_hit  = False
    evasion_hit    = False
    network_hit    = False
    persist_hit    = False
    gpa_hit        = False
    ll_hit         = False
    total_imports  = 0
    suspicious_imp = 0

    n_dlls = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        n_dlls = len(pe.DIRECTORY_ENTRY_IMPORT)
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name is None:
                    continue
                try:
                    name_lc = imp.name.decode("utf-8", errors="ignore").lower()
                except Exception:
                    continue
                total_imports += 1

                if name_lc in INJECTION_APIS:
                    injection_hit   = True
                    suspicious_imp += 1
                if name_lc in EVASION_APIS:
                    evasion_hit     = True
                    suspicious_imp += 1
                if name_lc in NETWORK_APIS:
                    network_hit     = True
                    suspicious_imp += 1
                if name_lc in PERSISTENCE_APIS:
                    persist_hit     = True
                    suspicious_imp += 1

    feats["suspicious_import_count"]  = float(suspicious_imp)
    feats["has_injection_imports"]    = 1.0 if injection_hit  else 0.0
    feats["has_evasion_imports"]      = 1.0 if evasion_hit    else 0.0
    feats["has_network_imports"]      = 1.0 if network_hit    else 0.0
    feats["has_persistence_imports"]  = 1.0 if persist_hit    else 0.0
    feats["import_count"]             = float(min(total_imports, 500))
    feats["n_imported_dlls"]          = float(min(n_dlls, 50))

    # ── Section analysis ──────────────────────────────────────────────────────
    entropies          = []
    has_unusual_sec    = False
    rx_rw              = False
    entry_outside_text = False
    text_section_va    = None
    text_section_end   = None

    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    except Exception:
        ep = 0

    if hasattr(pe, "sections"):
        for sec in pe.sections:
            try:
                name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore").lower()
            except Exception:
                name = ""
            data = sec.get_data()
            ent  = _section_entropy(data)
            entropies.append(ent)

            if name in UNUSUAL_SECTIONS or any(u in name for u in UNUSUAL_SECTIONS):
                has_unusual_sec = True

            # Executable + writable section
            flags = sec.Characteristics
            if (flags & 0x20000000) and (flags & 0x80000000):  # IMAGE_SCN_MEM_EXECUTE + WRITE
                rx_rw = True

            if name == ".text":
                text_section_va  = sec.VirtualAddress
                text_section_end = sec.VirtualAddress + sec.Misc_VirtualSize

        # Check if entry point is inside .text
        if text_section_va is not None:
            if not (text_section_va <= ep < text_section_end):
                entry_outside_text = True
        elif ep > 0:
            entry_outside_text = True

    feats["max_section_entropy"]     = max(entropies)   if entropies else 0.0
    feats["avg_section_entropy"]     = (sum(entropies) / len(entropies)) if entropies else 0.0
    feats["n_sections"]              = float(len(entropies))
    feats["has_unusual_section_name"] = 1.0 if has_unusual_sec    else 0.0
    feats["rx_rw_section"]           = 1.0 if rx_rw               else 0.0
    feats["entry_outside_text"]      = 1.0 if entry_outside_text  else 0.0

    # ── PE header anomalies ───────────────────────────────────────────────────
    try:
        ts   = pe.FILE_HEADER.TimeDateStamp
        year = datetime.datetime(1970, 1, 1).year + ts // (365 * 24 * 3600)
        feats["timestamp_anomaly"] = 1.0 if ts == 0 or year > 2030 or year < 2000 else 0.0
    except Exception:
        feats["timestamp_anomaly"] = 0.0

    try:
        chk = pe.OPTIONAL_HEADER.CheckSum
        feats["checksum_mismatch"] = 1.0 if chk == 0 else 0.0
    except Exception:
        feats["checksum_mismatch"] = 0.0

    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"]]
        )
        feats["has_tls"] = 1.0 if hasattr(pe, "DIRECTORY_ENTRY_TLS") else 0.0
    except Exception:
        feats["has_tls"] = 0.0

    try:
        chars = pe.FILE_HEADER.Characteristics
        feats["is_dll"] = 1.0 if (chars & 0x2000) else 0.0
    except Exception:
        feats["is_dll"] = 0.0

    # Overlay: data after last section
    try:
        last_sec  = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
        end_off   = last_sec.PointerToRawData + last_sec.SizeOfRawData
        overlay   = len(raw_bytes) - end_off
        feats["overlay_present"] = 1.0 if overlay > 512 else 0.0
    except Exception:
        feats["overlay_present"] = 0.0

    # Fix 4 — Real Windows certificate chain verification
    # Uses PowerShell Get-AuthenticodeSignature to validate the FULL trust chain,
    # not just whether the signature directory field is non-zero (easily faked).
    try:
        from bridge.cert_verifier import verify_signature
        cert_info = verify_signature(filepath)
        feats["is_signed"]      = float(cert_info["is_signed"])
        feats["signer_trusted"] = float(cert_info["signer_trusted"])
        # Store publisher name as metadata (not in ML feature vector)
        feats["_signer_name"]   = cert_info.get("signer_name", "")
        feats["_cert_status"]   = cert_info.get("cert_status", "")
    except Exception:
        feats["is_signed"]      = 0.0
        feats["signer_trusted"] = 0.0

    # Fix 5 — Anti-fat-padding: use actual PE code size, not raw file size.
    # Malware can pad a 1MB EXE with 59MB of zeros to exceed the 50MB cap.
    # actual_pe_size = headers + sum of all section raw data = real code size.
    try:
        _header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        _code_size   = sum(s.SizeOfRawData for s in pe.sections) + _header_size
        _actual_mb   = _code_size / (1024 * 1024)
        _padding_ratio = ((len(raw_bytes) - _code_size) / len(raw_bytes)) if raw_bytes else 0
        feats["has_padding"] = 1.0 if _padding_ratio > 0.40 else 0.0  # >40% padding = suspicious
    except Exception:
        _actual_mb = len(raw_bytes) / (1024 * 1024) if raw_bytes else 0
        feats["has_padding"] = 0.0

    # has_version_info + has_manifest
    # Threshold is now based on ACTUAL PE code size, not padded file size.
    has_version_info = False
    has_manifest     = False
    if _actual_mb <= 50:
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                RT_VERSION  = 16
                RT_MANIFEST = 24
                for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    rid = rsrc.id if rsrc.id else 0
                    if rid == RT_VERSION:
                        has_version_info = True
                    if rid == RT_MANIFEST:
                        has_manifest = True
        except Exception:
            pass
    feats["has_version_info"] = 1.0 if has_version_info else 0.0
    feats["has_manifest"]     = 1.0 if has_manifest     else 0.0

    pe.close()

    # ── String analysis (on raw bytes) ────────────────────────────────────────
    if raw_bytes:
        url_count  = len(re.findall(rb"https?://", raw_bytes, re.IGNORECASE))
        ip_count   = len(re.findall(
            rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_bytes
        ))
        susp_str   = sum(1 for p in SUSPICIOUS_STRINGS if p in raw_bytes)
        feats["url_count"]              = float(min(url_count, 50))
        feats["suspicious_string_count"] = float(susp_str)
        feats["ip_pattern_count"]       = float(min(ip_count, 50))
    else:
        feats["url_count"]              = 0.0
        feats["suspicious_string_count"] = 0.0
        feats["ip_pattern_count"]       = 0.0

    return feats
