@echo off
REM ============================================================
REM build.bat -- Compile sandbox_core.asm into sandbox_core.dll
REM Run this from: sandbox_core\ folder
REM ============================================================

set NASM=C:\mingw32\bin\nasm.exe
set GCC=C:\Qt\Tools\mingw1310_64\bin\gcc.exe
REM NOTE: C:\mingw32\bin\gcc.exe is 32-bit (i686) — cannot link 64-bit NASM objects
REM       C:\Qt\Tools\mingw1310_64\bin\gcc.exe is 64-bit (x86_64) — correct!

echo [1/3] Assembling sandbox_core.asm...
%NASM% -f win64 sandbox_core.asm -o sandbox_core.obj
if errorlevel 1 (
    echo [ERROR] Assembly failed.
    pause & exit /b 1
)
echo       OK

echo [2/3] Linking sandbox_core.obj into sandbox_core.dll...
%GCC% -shared -o sandbox_core.dll sandbox_core.obj --export-all-symbols -Wl,--enable-auto-image-base
if errorlevel 1 (
    echo [ERROR] Linking failed.
    pause & exit /b 1
)
echo       OK

echo [3/3] Cleaning up...
del sandbox_core.obj

echo.
echo [DONE] sandbox_core.dll built successfully.
echo Run:   cd .. ^&^& python sandbox_core\test_bridge.py
