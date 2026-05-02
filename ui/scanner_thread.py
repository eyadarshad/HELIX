"""
scanner_thread.py — Background worker thread for sandbox scanning (Production v3)

Scan pipeline (parallel where possible):
    ┌── VT hash check (background thread, 3s max) ──┐
    │                                               ├── merge results
    └── PE static analysis (main scan work)  ───────┘
    └── Behavioral sandbox emulation (graceful fallback)
    └── ML classification

VT and PE run AT THE SAME TIME — total scan time = max(VT, PE), not VT+PE.

Signals:
    progress(int)      — 0..100
    result(dict, list) — (feature_dict, opcode_list)
    error(str)         — error message
    status(str)        — status bar text
"""

import threading
from PyQt6.QtCore import QThread, pyqtSignal


class ScannerThread(QThread):
    progress = pyqtSignal(int)
    result   = pyqtSignal(dict, list)
    error    = pyqtSignal(str)
    status   = pyqtSignal(str)

    def __init__(self, filepath: str, max_instructions: int = 3000):
        super().__init__()
        self.filepath         = filepath
        self.max_instructions = max_instructions

    def run(self):
        try:
            name = self.filepath.replace("\\", "/").split("/")[-1]
            self.status.emit(f"Loading: {name}")
            self.progress.emit(5)

            # ── Phase 0: Launch VT check in background — runs PARALLEL to PE scan ──
            # VT starts immediately; PE scan proceeds without waiting for VT.
            # At the end we merge results. Zero added latency.
            vt_result   = None
            file_sha256 = ""
            _vt_done    = threading.Event()

            def _run_vt():
                nonlocal vt_result, file_sha256
                try:
                    from bridge.vt_check import check_hash, sha256_of_file
                    file_sha256 = sha256_of_file(self.filepath)
                    vt_result   = check_hash(self.filepath)   # 3s max timeout
                except Exception:
                    pass
                finally:
                    _vt_done.set()

            threading.Thread(target=_run_vt, daemon=True).start()

            # ── Format gate — reject file types the model wasn't trained on ────────
            import os as _os
            _ext = _os.path.splitext(self.filepath)[1].lower()

            _UNSUPPORTED = {".msi", ".bat", ".ps1", ".cmd", ".vbs", ".py", ".jar"}
            if _ext in _UNSUPPORTED:
                _vt_done.wait(timeout=3.5)   # still capture VT result if available
                if vt_result:
                    from bridge.vt_check import vt_verdict_to_score
                    vt_score = vt_verdict_to_score(vt_result)
                    if vt_score is not None and vt_score > 0.80:
                        # VT knows this hash — trust it
                        self.progress.emit(100)
                        self.result.emit({
                            "_file": self.filepath, "_sha256": file_sha256,
                            "_vt": vt_result, "_vt_score": vt_score,
                            "_vt_bypass": True, "_opcodes": 0,
                            "_summary": {}, "_packed": False,
                        }, [])
                        return
                # Cannot analyze — show unsupported format error, don't guess
                self.error.emit(
                    f"Unsupported format: {_ext.upper()} files cannot be analyzed by HELIX.\n\n"
                    f"HELIX is trained on PE executables (EXE/DLL).\n"
                    f"MSI, BAT, PS1, PY support will be added in a future release.\n"
                    f"VirusTotal result: {vt_result.get('vt_verdict', 'unknown') if vt_result else 'not checked'}"
                )
                return

            # DLLs pass through with a lower-confidence note
            _low_confidence = (_ext == ".dll")

            # ── Packer Detection + UPX Decompression (Fix 1) ──────────────────────
            # Checks section names, magic bytes, and entropy for known packers.
            # If UPX is detected AND `upx` binary is on PATH, decompresses to temp
            # file and scans the REAL payload. Otherwise proceeds with static features
            # (the high entropy is still a strong malware signal in the ML model).
            from bridge.unpacker import detect_packer, try_upx_decompress
            _is_packed, _packer_name = detect_packer(self.filepath)
            _scan_path   = self.filepath   # may be replaced by unpacked temp file
            _temp_unpacked = None

            if _is_packed:
                if _packer_name == "UPX":
                    self.status.emit(f"UPX packer detected — attempting decompression…")
                    self.progress.emit(13)
                    _temp_unpacked = try_upx_decompress(self.filepath)
                    if _temp_unpacked:
                        _scan_path = _temp_unpacked
                        self.status.emit("UPX decompressed — scanning real payload…")
                    else:
                        self.status.emit(f"UPX detected (upx not installed) — scanning stub…")
                else:
                    self.status.emit(f"Packer detected: {_packer_name} — scanning with static features…")

            # ── Phase 1: Static PE analysis (while VT runs in background) ──────────
            self.status.emit("Static PE analysis (imports, entropy, signature)…")
            self.progress.emit(15)
            from features.extractor import extract_features
            pe_feats_raw = extract_pe_features_safe(_scan_path)

            # ── Phase 2: Behavioral sandbox (graceful fallback) ────────────────────
            opcode_seq    = []
            trace_summary = {}
            packed        = False

            try:
                from bridge.disassembler     import disassemble_exe
                from bridge.sandbox_bridge   import SandboxBridge
                from bridge.trace_parser     import snapshot_step, build_trace_summary
                from bridge.sandbox_executor import _execute_instruction

                self.status.emit("Disassembling binary…")
                self.progress.emit(20)

                instructions = disassemble_exe(_scan_path, self.max_instructions)
                if instructions:
                    total = len(instructions)
                    self.status.emit(f"Emulating {total} instructions…")
                    self.progress.emit(25)

                    sb    = SandboxBridge()
                    sb.init()
                    steps = []

                    for i, (mnem, op_str, addr) in enumerate(instructions):
                        opcode = mnem.upper()
                        opcode_seq.append(opcode)
                        _execute_instruction(sb, opcode, op_str, i)
                        sb.record(opcode)
                        steps.append(snapshot_step(sb, opcode, op_str))

                        if i % max(total // 20, 1) == 0:
                            pct = 25 + int((i / total) * 55)
                            self.progress.emit(pct)

                    trace_summary = build_trace_summary(sb, steps)
                else:
                    packed = True
                    self.status.emit("Packed binary — static features only…")

            except Exception:
                packed = True
                self.status.emit("Emulation unavailable — static features only…")

            # ── Phase 3: Wait for VT (at most 3.5s from now, usually already done) ─
            self.status.emit("Finalising (waiting for VirusTotal check)…")
            self.progress.emit(90)
            _vt_done.wait(timeout=3.5)   # won't block long — VT already running

            # ── Phase 4: Check VT — instant exit if known malware hash ─────────────
            from bridge.vt_check import vt_verdict_to_score
            vt_score = vt_verdict_to_score(vt_result)

            if vt_score is not None and vt_score > 0.80:
                self.status.emit(
                    f"Known threat — {vt_result.get('vt_malicious','?')}"
                    f"/{vt_result.get('vt_total','?')} AV engines flagged"
                )
                self.progress.emit(100)
                self.result.emit({
                    "_file":     self.filepath,
                    "_sha256":   file_sha256,
                    "_vt":       vt_result,
                    "_vt_score": vt_score,
                    "_opcodes":  0,
                    "_summary":  {},
                    "_packed":   False,
                    "_vt_bypass": True,
                }, [])
                return

            # ── Phase 5: Build feature vector + ML classification ──────────────────
            self.status.emit("Building feature vector…")
            features = extract_features(trace_summary, filepath=_scan_path)
            features["_file"]         = self.filepath   # always show original filename
            features["_sha256"]       = file_sha256
            features["_vt"]           = vt_result
            features["_vt_score"]     = vt_score
            features["_opcodes"]      = len(opcode_seq)
            features["_summary"]      = trace_summary
            features["_packed"]       = packed or _is_packed
            features["_packer_name"]  = _packer_name

            self.progress.emit(100)
            self.result.emit(features, opcode_seq)

        except FileNotFoundError as e:
            self.error.emit(f"File not found:\n{e}")
        except ValueError as e:
            self.error.emit(f"Invalid file format:\n{e}")
        except Exception as e:
            self.error.emit(f"Scan failed:\n{type(e).__name__}: {e}")
        finally:
            # Clean up temp unpacked file if one was created
            if _temp_unpacked and os.path.exists(_temp_unpacked):
                try:
                    os.remove(_temp_unpacked)
                except Exception:
                    pass


def extract_pe_features_safe(filepath: str) -> dict:
    """No-throw wrapper around extract_pe_features."""
    try:
        from features.pe_extractor import extract_pe_features
        return extract_pe_features(filepath)
    except Exception:
        return {}
