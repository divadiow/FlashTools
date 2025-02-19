@echo off
setlocal EnableDelayedExpansion

echo ================================================
echo       RTL AmebaZ Bootloader Utility 0.1 - Menu
echo ================================================
echo.
echo Select an operation:
echo   1. Read Flash (rf)
echo   2. Write Flash (wf)
echo   3. Write SRAM (wm)
echo   4. Erase Flash Sectors (es)
echo   5. Erase 2MB Flash Chip (0x0 to 0x200000)
echo   6. Get Flash Status (gf)
echo.
set /p op="Enter your choice (1-6): "

set /p comport="Enter COM Port (e.g., COM65): "

if "%op%"=="1" (
    echo --- Read Flash Selected ---
    echo *** use example addresses if uncertain ***
    set /p start_addr="Enter start address (e.g., 0x0): "
    set /p size="Enter size of region (e.g., 0x200000): "
    set /p filename="Enter filename to save flash dump: "
    echo.
    echo Running: python rtltool.py --port !comport! rf !start_addr! !size! !filename!
    python rtltool.py --port !comport! rf !start_addr! !size! !filename!
) else if "%op%"=="2" (
    echo --- Write Flash Selected ---
    set /p start_addr="Enter start address (e.g., 0x0): "
    set /p filename="Enter filename to write flash from: "
    echo.
    echo Running: python %~dp0rtltool.py --port !comport! wf !start_addr! !filename!
    python %~dp0rtltool.py --port !comport! wf !start_addr! !filename!
) else if "%op%"=="3" (
    echo --- Write SRAM Selected ---
    set /p start_addr="Enter start address (e.g., 0x0): "
    set /p filename="Enter filename to write SRAM from: "
    echo.
    echo Running: python %~dp0rtltool.py --port !comport! wm !start_addr! !filename!
    python %~dp0rtltool.py --port !comport! wm !start_addr! !filename!
) else if "%op%"=="4" (
    echo --- Erase Flash Sectors Selected ---
    set /p start_addr="Enter start address (e.g., 0x0): "
    set /p size="Enter size of region (e.g., 0x200000): "
    echo.
    echo Running: python %~dp0rtltool.py --port !comport! es !start_addr! !size!
    python %~dp0rtltool.py --port !comport! es !start_addr! !size!
) else if "%op%"=="5" (
    echo --- Erase 2MB Flash Chip Selected ---
    echo Erasing flash from address 0x0 to 0x200000...
    echo.
    echo Running: python rtltool.py --port !comport! es 0x0 0x200000
    python rtltool.py --port !comport! es 0x0 0x200000
) else if "%op%"=="6" (
    echo --- Get Flash Status Selected ---
    echo.
    echo Running: python rtltool.py --port !comport! gf
    python rtltool.py --port !comport! gf
) else (
    echo Invalid option.
)

pause
