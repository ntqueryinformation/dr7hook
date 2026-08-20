@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
  echo VCVARS FAILED
  exit /b 1
)
del /q obj_*.obj 2>nul
cl /nologo /std:c++17 /W4 /EHsc /c examples\internal_example.cpp /Fo:obj_internal_example.obj || exit /b 1
link /nologo /DLL obj_internal_example.obj /OUT:internal_example.dll user32.lib || exit /b 1
cl /nologo /std:c++17 /W4 /EHsc examples\internal_host.cpp /Fe:internal_host.exe /Fo:obj_internal_host.obj /link user32.lib || exit /b 1
cl /nologo /std:c++17 /W4 /EHsc examples\target.cpp /Fe:target.exe /Fo:obj_target.obj || exit /b 1
cl /nologo /std:c++17 /W4 /EHsc examples\external_example.cpp /Fe:external_example.exe /Fo:obj_external_example.obj || exit /b 1
cl /nologo /std:c++17 /W4 /EHsc examples\redirect_example.cpp /Fe:redirect_example.exe /Fo:obj_redirect_example.obj || exit /b 1
cl /nologo /std:c++17 /W4 /EHsc examples\test_injector.cpp /Fe:test_injector.exe /Fo:obj_test_injector.obj || exit /b 1
echo BUILD_OK
