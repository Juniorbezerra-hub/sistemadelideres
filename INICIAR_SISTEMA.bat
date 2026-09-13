@echo off
title Sistema de Evolucao de Lideres - JR Telecom
cd /d "%~dp0backend"

if not exist node_modules (
  echo.
  echo Instalando dependencias pela primeira vez, aguarde...
  echo.
  call npm install
  if errorlevel 1 (
    echo.
    echo ERRO ao instalar dependencias. Verifique se o Node.js esta instalado.
    pause
    exit /b 1
  )
)

start "Sistema Evolucao Lideres - Servidor (NAO FECHE)" cmd /k "node --no-warnings server.js"
timeout /t 2 /nobreak >nul
start "" http://localhost:3800
