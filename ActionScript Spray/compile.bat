echo off
cls
cd ..
cd flash-dev/bin
mxmlc.exe ../../flash-code/main.as -o ../../flash-code/test.swf -static-link-runtime-shared-libraries
pause