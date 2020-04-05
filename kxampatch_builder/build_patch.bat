@echo off

rem Some cleanup
del /Q kxam.patch patches.elf

if not exist patches.S goto NOFILE1
echo Calling assembler
bin\xenon-as.exe -be -many patches.S -o patches.elf

if not exist patches.elf goto NOFILE2
echo Calling objcopy
bin\xenon-objcopy.exe patches.elf -O binary kxam.patch
del /q patches.elf

if not exist kxam.patch goto NOFILE2

:NONP
echo.
echo ** SUCCESS! Patches Complete **
goto EXIT

:NOFILE1
echo.
echo patches.S missing, cannot proceed
goto EXIT

:NOFILE2
echo.
echo patches.elf did not assemble, cannot proceed
goto EXIT

:NOFILE3
echo.
echo kxam.patch did not build
goto EXIT

:EXIT
pause
exit
