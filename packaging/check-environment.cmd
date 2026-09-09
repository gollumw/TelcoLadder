@echo off
rem TelcoLadder portable - environment check.
rem
rem Runs the bundled telcoladder.exe's own `check`: it locates tshark.exe
rem (Wireshark 4.0 or newer, in its default Program Files location or through
rem the TELCOLADDER_TSHARK variable) and verifies the dissectors it needs.
rem Nothing is installed or modified.

cd /d "%~dp0"
telcoladder.exe check
if errorlevel 1 (
  echo.
  echo tshark.exe was not found, or the Wireshark install is too old.
  echo Install Wireshark 4.0 or newer from https://www.wireshark.org/download.html
  echo - the default install location is searched automatically - or set
  echo TELCOLADDER_TSHARK to the full path of tshark.exe and run this again.
)
echo.
pause
