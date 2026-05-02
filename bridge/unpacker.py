"""
unpacker.py — Packer Detection & UPX Decompression

Detects known packers from PE section names / magic bytes and attempts
to automatically decompress UPX-packed files so the full feature
extractor can run on the real payload instead of the packer stub.

Supported packers (detection only, not decompression):
    UPX, MPRESS, PECompact, Themida, ASPack, FSG, NsPack, PEtite

UPX decompression (if `upx` binary is on PATH or in WORKSPACE/tools):
    upx --decompress --force -o <temp_file> <original_file>
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile

# ── Known packer fingerprints (section name → packer name) ────────────────────
_PACKER_SECTIONS: dict[str, str] = {
    "upx0":      "UPX",
    "upx1":      "UPX",
    "upx2":      "UPX",
    ".upx":      "UPX",
    "mpress1":   "MPRESS",
    "mpress2":   "MPRESS",
    ".petite":   "PEtite",
    ".nsp0":     "NsPack",
    ".nsp1":     "NsPack",
    ".nsp2":     "NsPack",
    ".aspack":   "ASPack",
    ".adata":    "ASPack",
    "themida":   "Themida",
    "winlicen":  "Themida",
    ".packed":   "Generic",
    "fsg!":      "FSG",
    ".fsg":      "FSG",
    ".pec2":     "PECompact",
    "pecompact": "PECompact",
}

# ── Magic byte fingerprints checked in the overlay / entry section ─────────────
_MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"UPX!",  "UPX"),
    (b"MPRESS", "MPRESS"),
    (b"\x60\xbe", "Possible UPX stub"),   # pushad + mov esi, ... typical UPX opener
]


def detect_packer(filepath: str) -> tuple[bool, str]:
    """
    Inspect a PE file for known packer signatures.

    Returns:
        (is_packed: bool, packer_name: str)
        packer_name is '' if not packed.
    """
    try:
        import pefile
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories(directories=[])

        for section in pe.sections:
            raw_name = section.Name.rstrip(b"\x00").decode("ascii", errors="ignore").lower()
            if raw_name in _PACKER_SECTIONS:
                pe.close()
                return True, _PACKER_SECTIONS[raw_name]

        # Check magic bytes in raw file
        with open(filepath, "rb") as f:
            raw = f.read(min(1024 * 1024, os.path.getsize(filepath)))  # first 1 MB
        for magic, name in _MAGIC_SIGNATURES:
            if magic in raw:
                pe.close()
                return True, name

        # High overall entropy with single or two sections is a strong packer hint
        entropies = [s.get_entropy() for s in pe.sections]
        if len(entropies) <= 3 and entropies and max(entropies) > 7.2:
            pe.close()
            return True, "UnknownPacker"

        pe.close()
        return False, ""

    except Exception:
        return False, ""


def try_upx_decompress(filepath: str) -> str | None:
    """
    Attempt to decompress a UPX-packed file using the `upx` binary.

    Looks for `upx` on PATH first, then in Workspace/tools/upx.exe.

    Returns:
        Path to the DECOMPRESSED temporary file if successful, else None.
        Caller is responsible for deleting the temp file after use.
    """
    upx_bin = _find_upx()
    if not upx_bin:
        return None  # UPX not installed — detection still works, just no decompression

    try:
        fd, tmp_path = tempfile.mkstemp(suffix=".exe", prefix="helix_unpack_")
        os.close(fd)
        os.remove(tmp_path)  # upx needs the file to NOT exist

        result = subprocess.run(
            [upx_bin, "--decompress", "--force", "-o", tmp_path, filepath],
            capture_output=True,
            timeout=30,
        )

        if result.returncode == 0 and os.path.exists(tmp_path):
            return tmp_path
        else:
            # Clean up on failure
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            return None

    except Exception:
        return None


def _find_upx() -> str | None:
    """Find the upx binary on PATH or in project tools/ directory."""
    # 1. Check PATH
    upx = shutil.which("upx")
    if upx:
        return upx

    # 2. Check PROJECT/tools/upx.exe
    workspace = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    local_upx = os.path.join(workspace, "tools", "upx.exe")
    if os.path.exists(local_upx):
        return local_upx

    return None
