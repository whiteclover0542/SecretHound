@echo off
rem secrethound launcher.
rem
rem KEEP THIS FILE PURE ASCII. cmd.exe reads a batch file using the current code
rem page, so "chcp 65001" below shifts how the rest of this same file is decoded.
rem With non-ASCII text in the file, cmd loses its byte offset and starts running
rem fragments of later lines. Every Korean message therefore lives in the exe,
rem which prints UTF-8 that the console can render once the code page is set.
rem The folder picker is "secrethound check --pick" for the same reason.
rem
rem Two ways to use this:
rem   1. double-click it (or the shortcut) and pick a folder in the dialog
rem   2. drag a folder onto it to scan that folder right away

chcp 65001 > nul
title secrethound

rem Reports go next to this file, not into the scanned folder: the scanned folder
rem is usually a git repo and the report would end up committed. "%~dp0." keeps a
rem trailing dot so the path never ends in a backslash, which would escape the quote.

if "%~1"=="" (
  "%~dp0secrethound.exe" check --pick --out "%~dp0."
) else (
  "%~dp0secrethound.exe" check "%~1" --out "%~dp0."
)

echo.
pause
