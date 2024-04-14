# Pkcs7SignatureGenerator

Sample application for PKCS#7/CMS/SMIME signature creation with [Pkcs11Interop](https://pkcs11interop.net), [BouncyCastle](https://bouncycastle.org/csharp/) and [MimeKit](https://mimekit.net) libraries.

## Basic usage

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

## Detached CMS signature

### Generation of detached CMS signature

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
		--signature-scheme "RSASSA_PKCS1_v1_5"
		--output-format "CMS"
		--certs-dir "c:\temp\additional-certs"

### Verification of detached CMS signature

	openssl.exe
		cms
		-verify
		-binary
		-inform DER
		-in "c:\temp\document.p7s"
		-content "c:\temp\document.txt"
		-noverify
		> nul

## Detached SMIME signature

### Generation of detached SMIME signature

	Pkcs7SignatureGenerator.exe
		--pkcs11-library "softhsm2.dll"
		--sign
		--token-serial "864c60e98638f74e"
		--token-label "My token 1"
		--pin "11111111"
		--key-label "John Doe"
		--key-id "4A6F686E20446F65"
		--data-file "c:\temp\document.txt"
		--signature-file "c:\temp\document.eml"
		--hash-alg "SHA256"
		--signature-scheme "RSASSA_PKCS1_v1_5"
		--output-format "SMIME"
		--certs-dir "c:\temp\additional-certs"

### Verification of detached SMIME signature

	openssl.exe
		smime
		-verify
		-in "c:\temp\document.eml"
		-noverify
		> nul
