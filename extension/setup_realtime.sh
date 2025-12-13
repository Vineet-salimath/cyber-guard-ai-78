#!/bin/bash

# Real-Time Symbol & Alert Updates - Setup Script
# This script helps integrate the real-time system into your extension

echo "🛡️  MalwareSnipper Real-Time Symbol & Alert Updates - Setup"
echo "========================================================="
echo ""

# Check if we're in the right directory
if [ ! -f "manifest.json" ]; then
    echo "❌ Error: manifest.json not found"
    echo "Please run this script from the extension directory"
    exit 1
fi

echo "✓ Extension directory found"
echo ""

# List files to verify
echo "📁 Checking required files..."
echo ""

files_to_check=(
    "symbolManager.js"
    "alertManager.js"
    "popup_realtime_enhanced.js"
    "realtimeWebSocket.js"
    "realtime_animations.css"
)

all_present=true
for file in "${files_to_check[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ $file"
    else
        echo "❌ $file (MISSING)"
        all_present=false
    fi
done

echo ""

if [ "$all_present" = false ]; then
    echo "⚠️  Some files are missing. Please ensure all files are in the extension directory."
    exit 1
fi

echo "✅ All required files present!"
echo ""

# Check manifest.json
echo "🔍 Checking manifest.json..."
if grep -q '"action"' manifest.json; then
    echo "✅ 'action' permission found"
else
    echo "⚠️  'action' permission may be missing"
fi

if grep -q 'symbolManager.js' manifest.json; then
    echo "✅ symbolManager.js in manifest"
else
    echo "⚠️  symbolManager.js not in manifest"
fi

echo ""
echo "📝 Next steps:"
echo "1. Update popup.html to include new scripts:"
echo ""
echo "   <script src=\"symbolManager.js\"></script>"
echo "   <script src=\"alertManager.js\"></script>"
echo "   <script src=\"popup_realtime_enhanced.js\"></script>"
echo "   <link rel=\"stylesheet\" href=\"realtime_animations.css\">"
echo ""
echo "2. Go to chrome://extensions/"
echo "3. Toggle off and on the MalwareSnipper extension"
echo "4. Check the console for initialization messages"
echo ""
echo "5. Open the extension popup and verify:"
echo "   ✓ Status card displays correctly"
echo "   ✓ Alerts list is visible"
echo "   ✓ No console errors (F12)"
echo ""
echo "✨ Real-time system ready for testing!"
