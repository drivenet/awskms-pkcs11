@echo off
rmdir /s /q packages\linux-x64\awskms-pkcs11
mkdir packages\linux-x64\awskms-pkcs11
dotnet publish AwsKmsPkcs11 --force --output packages\linux-x64\awskms-pkcs11 -c Integration -r linux-x64 --no-self-contained
