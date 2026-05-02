"""
startup.py — Windows startup registration / unregistration

Adds or removes the MalwareSandbox AI tray app from Windows startup
by writing to HKCU\Software\Microsoft\Windows\CurrentVersion\Run

Usage:
    from ui.startup import register_startup, unregister_startup, is_registered
"""

from __future__ import annotations
import os
import sys

# Registry key for current-user startup programs
REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
APP_NAME  = "HELIX"


def _get_launch_cmd() -> str:
    """Return the exact command to launch the tray app."""
    python  = sys.executable
    tray    = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "main.py"
    )
    return f'"{python}" "{tray}" --tray'


def register_startup() -> bool:
    """
    Register the tray app to launch at Windows startup.
    Returns True on success, False on failure.
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, REG_PATH,
            0, winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _get_launch_cmd())
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"[Startup] Failed to register: {e}")
        return False


def unregister_startup() -> bool:
    """
    Remove the startup entry.
    Returns True on success (or if never registered).
    """
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, REG_PATH,
            0, winreg.KEY_SET_VALUE
        )
        winreg.DeleteValue(key, APP_NAME)
        winreg.CloseKey(key)
        return True
    except FileNotFoundError:
        return True   # wasn't registered — that's fine
    except Exception as e:
        print(f"[Startup] Failed to unregister: {e}")
        return False


def is_registered() -> bool:
    """Check if the startup entry exists."""
    try:
        import winreg
        key  = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH)
        val, _ = winreg.QueryValueEx(key, APP_NAME)
        winreg.CloseKey(key)
        return bool(val)
    except Exception:
        return False
