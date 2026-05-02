/*
 * dllmain.c — Minimal DLL entry point for sandbox_core.dll
 *
 * GCC needs this to properly link a shared library on Windows.
 * All actual sandbox logic is in sandbox_core.asm (NASM x64).
 */
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    (void)hModule; (void)dwReason; (void)lpReserved;
    return TRUE;
}
