@echo off
whoami /groups | find "S-1-16-12288" >nul
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
chcp 65001 >nul
set "JAVAW=%USERPROFILE%\.jdks\ms-17.0.18\bin\javaw.exe"
if not exist "%JAVAW%" (
    echo ERRO: JDK 17 não encontrado em:
    echo   %JAVAW%
    echo.
    echo O Analisador de Pacotes precisa do Java 17. Instale o JDK 17 nessa pasta
    echo ^(no IntelliJ: File ^> Project Structure ^> SDKs ^> Download JDK ^> versão 17^)
    echo ou ajuste o caminho na linha "set JAVAW=" deste arquivo.
    echo.
    pause
    exit /b 1
)
start "" "%JAVAW%" -jar "target\analisador-de-pacotes-1.0.0-shaded.jar"
