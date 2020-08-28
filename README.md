# awskms-pkcs11
## What it is and why it was created?
This is a simple AWS KMS to YubiKey PKCS#11 bridge built with ASP.NET Core that supports only a minimal subset of KMS methods (`DescribeKey`, `Encrypt` and `Decrypt`) using RSA encryption.

## Systemd
It has full support for running via `systemd`, including `Type=notify` unit, socket inheritance via Libuv, journald logging, etc.
