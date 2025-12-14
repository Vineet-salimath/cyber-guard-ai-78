Write-Host "`n🔍 VERIFYING NEW ARCHITECTURE..." -ForegroundColor Cyan

$errors = @()

# Check backend file
if (Test-Path "backend\app.py") {
    $content = Get-Content "backend\app.py" -Raw
    if ($content -like "*chrome-extension://*") {
        Write-Host "✅ Backend accepts chrome-extension origins" -ForegroundColor Green
    } else {
        Write-Host "❌ Backend missing chrome-extension origin!" -ForegroundColor Red
        $errors += "Backend"
    }
} else {
    Write-Host "❌ backend\app.py not found!" -ForegroundColor Red
    $errors += "Backend file"
}

# Check extension file
if (Test-Path "extension\background.js") {
    $content = Get-Content "extension\background.js" -Raw
    if ($content -like "*BACKEND_URL*" -and $content -like "*sendURLToBackend*") {
        Write-Host "✅ Extension sends to backend" -ForegroundColor Green
    } else {
        Write-Host "❌ Extension not configured for backend!" -ForegroundColor Red
        $errors += "Extension"
    }
} else {
    Write-Host "❌ extension\background.js not found!" -ForegroundColor Red
    $errors += "Extension file"
}

# Check dashboard file
if (Test-Path "src\pages\PureDashboard.tsx") {
    $content = Get-Content "src\pages\PureDashboard.tsx" -Raw
    if ($content -like "*PURE*" -and $content -like "*new_scan*") {
        Write-Host "✅ PureDashboard exists (pure listener)" -ForegroundColor Green
    } else {
        Write-Host "⚠️  PureDashboard may not be properly configured" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ src\pages\PureDashboard.tsx not found!" -ForegroundColor Red
    $errors += "Dashboard"
}

# Check routing
if (Test-Path "src\App.tsx") {
    $content = Get-Content "src\App.tsx" -Raw
    if ($content -like "*PureDashboard*") {
        Write-Host "✅ Routing configured for PureDashboard" -ForegroundColor Green
    } else {
        Write-Host "❌ Routing not updated!" -ForegroundColor Red
        $errors += "Routing"
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
if ($errors.Count -eq 0) {
    Write-Host "✅ ALL FILES VERIFIED!" -ForegroundColor Green
    Write-Host "Ready to run: .\START-NEW-ARCHITECTURE.ps1" -ForegroundColor White
} else {
    Write-Host "❌ ERRORS FOUND:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
}
Write-Host "========================================" -ForegroundColor Cyan
