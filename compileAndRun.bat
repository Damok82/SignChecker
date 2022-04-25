@echo off
cls

set message="Hello world"
set signature="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="

echo *** Checking with patched JAVA version ...
echo.

echo JDK 17.0.3
call javac.exe SignChecker.java
IF ERRORLEVEL 0 call java.exe SignChecker %message% %signature%
echo.

echo.

echo *** Checking with vulnerable JAVA version ...
echo.

echo JDK 17.0.2
call "C:\Program Files\Java\jdk-17.0.2\bin\javac.exe" SignChecker.java
IF ERRORLEVEL 0 call "C:\Program Files\Java\jdk-17.0.2\bin\java.exe" SignChecker %message% %signature%
echo.
