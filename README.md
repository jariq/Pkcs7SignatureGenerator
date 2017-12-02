Pkcs7SignatureGenerator
=======================

Example application for PKCS#7 signature creation with [Pkcs11Interop](http://www.pkcs11interop.net) and [BouncyCastle](http://www.bouncycastle.org/csharp/) libraries

## Usage

### List available tokens

	Pkcs7SignatureGenerator.exe
		--pkcs11-library "softhsm2.dll"
		--list-tokens

### List private keys and certificates on specified token

	Pkcs7SignatureGenerator.exe
		--pkcs11-library "softhsm2.dll"
		--list-objects
		--token-serial "864c60e98638f74e"
		--token-label "My token 1"
		--pin "11111111"

### Sign file

	Pkcs7SignatureGenerator.exe
		--pkcs11-library "softhsm2.dll"
		--sign
		--token-serial "864c60e98638f74e"
		--token-label "My token 1"
		--pin "11111111"
		--key-label "John Doe"
		--key-id "4A6F686E20446F65"
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
