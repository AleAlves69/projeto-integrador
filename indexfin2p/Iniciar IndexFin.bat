@echo off
setlocal
cd /d "%~dp0"
title IndexFin - servidor local

where python >nul 2>&1
if errorlevel 1 (
    echo Python nao foi encontrado. Instale o Python e tente novamente.
    pause
    exit /b 1
)

echo Iniciando IndexFin em http://127.0.0.1:5000
echo Mantenha esta janela aberta enquanto usar o sistema.
echo Para parar o servidor, pressione Ctrl+C nesta janela.
echo.

python app.py

echo.
echo O servidor IndexFin foi encerrado.
pause
