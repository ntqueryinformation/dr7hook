@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cl /nologo /std:c++17 /W4 /EHsc test_smoke.cpp /Fe:test_smoke.exe /Fo:obj_test_smoke.obj || exit /b 1
echo BUILD_OK
