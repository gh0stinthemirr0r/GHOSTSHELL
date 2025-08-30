# Test script for window control functionality
# This script demonstrates the different window control strategies

Write-Host "=== GhostShell Window Control Test ===" -ForegroundColor Cyan
Write-Host ""

# Test 1: Basic PowerShell command that might show a popup
Write-Host "Test 1: Running basic PowerShell command..." -ForegroundColor Yellow
Get-Process | Where-Object { $_.ProcessName -like "*powershell*" } | Select-Object ProcessName, Id, MainWindowTitle

Write-Host ""
Write-Host "Test 2: Running command that typically shows console window..." -ForegroundColor Yellow
# This command often triggers a console window
cmd /c "echo This command might show a console window & timeout /t 2 /nobreak > nul"

Write-Host ""
Write-Host "Test 3: Running nested PowerShell command..." -ForegroundColor Yellow
# This often creates a new PowerShell window
powershell -Command "Write-Host 'Nested PowerShell command executed' -ForegroundColor Green; Start-Sleep -Seconds 1"

Write-Host ""
Write-Host "Test 4: Running system information command..." -ForegroundColor Yellow
# System commands that might trigger UAC or console windows
systeminfo | Select-String "OS Name", "Total Physical Memory" | ForEach-Object { $_.Line }

Write-Host ""
Write-Host "=== Window Control Test Complete ===" -ForegroundColor Cyan
Write-Host "Check if any popup windows appeared during execution." -ForegroundColor White
Write-Host "The window controller should have:" -ForegroundColor White
Write-Host "  1. Hidden console windows completely" -ForegroundColor Green
Write-Host "  2. Resized popup windows to 1x1 pixel" -ForegroundColor Green  
Write-Host "  3. Moved windows off-screen" -ForegroundColor Green
Write-Host "  4. Applied the configured window strategy" -ForegroundColor Green
