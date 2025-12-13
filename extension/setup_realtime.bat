@echo off
REM Real-Time Symbol & Alert Updates - Setup Script for Windows
REM This script helps integrate the real-time system into your extension

setlocal enabledelayedexpansion

echo.
echo ════════════════════════════════════════════════════════════════
echo  🛡️  MalwareSnipper Real-Time Symbol ^& Alert Updates - Setup
echo ════════════════════════════════════════════════════════════════
echo.

REM Check if we're in the right directory
if not exist "manifest.json" (
    echo ❌ Error: manifest.json not found
    echo Please run this script from the extension directory
    pause
    exit /b 1
)

echo ✓ Extension directory found
echo.

REM List files to verify
echo 📁 Checking required files...
echo.

setlocal enabledelayedexpansion
set "all_present=true"

for %%F in (
    "symbolManager.js"
    "alertManager.js"
    "popup_realtime_enhanced.js"
    "realtimeWebSocket.js"
    "realtime_animations.css"
) do (
    if exist %%F (
        echo ✅ %%F
    ) else (
        echo ❌ %%F (MISSING)
        set "all_present=false"
    )
)

echo.

if "%all_present%"=="false" (
    echo ⚠️  Some files are missing. Please ensure all files are in the extension directory.
    pause
    exit /b 1
)

echo ✅ All required files present!
echo.

REM Check manifest.json
echo 🔍 Checking manifest.json...

findstr /M "\"action\"" manifest.json >nul
if %errorlevel% equ 0 (
    echo ✅ 'action' permission found
) else (
    echo ⚠️  'action' permission may be missing
)

findstr /M "symbolManager.js" manifest.json >nul
if %errorlevel% equ 0 (
    echo ✅ symbolManager.js in manifest
) else (
    echo ⚠️  symbolManager.js not in manifest
)

echo.
echo 📝 Next steps:
echo.
echo 1. Update popup.html to include new scripts:
echo.
echo    ^<script src="symbolManager.js"^>^</script^>
echo    ^<script src="alertManager.js"^>^</script^>
echo    ^<script src="popup_realtime_enhanced.js"^>^</script^>
echo    ^<link rel="stylesheet" href="realtime_animations.css"^>
echo.
echo 2. Go to chrome://extensions/
echo 3. Toggle off and on the MalwareSnipper extension
echo 4. Check the console for initialization messages
echo.
echo 5. Open the extension popup and verify:
echo    ✓ Status card displays correctly
echo    ✓ Alerts list is visible
echo    ✓ No console errors (F12)
echo.
echo ✨ Real-time system ready for testing!
echo.
pause
