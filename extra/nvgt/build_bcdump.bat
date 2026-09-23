@echo off
rem Build the optional owned-test host with a matching AngelScript + MinGW.
rem Usage: set NVGT_SOURCE=path-to-nvgt-checkout, then run this script.
rem Writes tests\nvgt\fixtures\build\bcdump.exe, where the NVGT tests look for it.
setlocal
if not defined NVGT_SOURCE (
  echo error: set NVGT_SOURCE to your matching NVGT source checkout.
  exit /b 1
)
set "NVGT_ROOT=%NVGT_SOURCE%"
if defined CXX (
  set "CXX_EXE=%CXX%"
) else (
  where g++.exe >nul 2>nul
  if errorlevel 1 (
    echo error: MinGW g++.exe not on PATH; set CXX to its executable path.
    exit /b 1
  )
  set "CXX_EXE=g++.exe"
)
set "WORKSPACE=%~dp0..\..\tests\nvgt\fixtures"
set "LIB=%NVGT_ROOT%\dep_angelscript\sdk\angelscript\projects\cmake\build_mingw\libangelscript.a"
if not exist "%LIB%" (
  echo error: libangelscript.a not found in NVGT_SOURCE; build the matching SDK first.
  exit /b 1
)
if not exist "%WORKSPACE%\build" mkdir "%WORKSPACE%\build"

"%CXX_EXE%" -std=c++17 -O2 -fuse-ld=lld -I"%NVGT_ROOT%\dep_angelscript\sdk\angelscript\include" ^
  -I"%NVGT_ROOT%\dep_angelscript\sdk\add_on" ^
  "%~dp0bcdump.cpp" ^
  "%NVGT_ROOT%\dep_angelscript\sdk\add_on\scriptbuilder\scriptbuilder.cpp" ^
  "%NVGT_ROOT%\dep_angelscript\sdk\add_on\scriptstdstring\scriptstdstring.cpp" ^
  "%NVGT_ROOT%\dep_angelscript\sdk\add_on\scriptarray\scriptarray.cpp" ^
  "%NVGT_ROOT%\dep_angelscript\sdk\add_on\scriptdictionary\scriptdictionary.cpp" ^
  "%NVGT_ROOT%\dep_angelscript\sdk\add_on\scripthandle\scripthandle.cpp" ^
  "%NVGT_ROOT%\dep_angelscript\sdk\add_on\scriptany\scriptany.cpp" ^
  "%NVGT_ROOT%\dep_angelscript\sdk\add_on\scriptmath\scriptmath.cpp" ^
  "%LIB%" -o "%WORKSPACE%\build\bcdump.exe" -static -lwinmm -Wl,--subsystem,console
if errorlevel 1 (
  echo build failed
  exit /b 1
)
echo built %WORKSPACE%\build\bcdump.exe
