@echo off
rmdir /s /q packages\linux-x64\awskms-pkcs11
mkdir packages\linux-x64\awskms-pkcs11
dotnet publish AwsKmsPkcs11 --force --output packages\linux-x64\awskms-pkcs11 -c Integration -r linux-x64 --self-contained false
move packages\linux-x64\awskms-pkcs11\Microsoft.Extensions.Hosting.Systemd.dll "%TEMP%"
del packages\linux-x64\awskms-pkcs11\web.config packages\linux-x64\awskms-pkcs11\*.deps.json packages\linux-x64\awskms-pkcs11\*settings.json packages\linux-x64\awskms-pkcs11\Microsoft.*.dll
move "%TEMP%\Microsoft.Extensions.Hosting.Systemd.dll" packages\linux-x64\awskms-pkcs11
