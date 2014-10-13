Pkcs7SignatureGenerator
=======================

Example application for PKCS#7 signature creation with [Pkcs11Interop](http://www.pkcs11interop.net) and [BouncyCastle](http://www.bouncycastle.org/csharp/) libraries

## Usage

### List available tokens

	Pkcs7SignatureGenerator.exe
		--pkcs11-library "siecap11.dll"
		--list-tokens

### List private keys and certificates on specified token

	Pkcs7SignatureGenerator.exe
		--pkcs11-library "siecap11.dll"
		--list-objects
		--token-serial "7BFF2737350B262C"
		--token-label "Pkcs11Interop"
		--pin "11111111"

### Sign file

	Pkcs7SignatureGenerator.exe
		--pkcs11-library "siecap11.dll"
		--sign
		--token-serial "7BFF2737350B262C"
		--token-label "Pkcs11Interop"
		--pin "11111111"
		--key-label "John Doe"
		--key-id "EC5E50A889B888D600C6E13CB0FDF0C1"
		--data-file "c:\temp\document.txt"
		--signature-file "c:\temp\document.p7s"
		--hash-alg "SHA256"
		--certs-dir "c:\temp\additional-certs"

### Verify signature

	openssl.exe
		smime
		-verify
		-binary
		-inform DER
		-in "c:\temp\document.p7s"
		-content "c:\temp\document.txt"
		-noverify
		> nul
