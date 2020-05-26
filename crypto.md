## PKCS #1: RSA Cryptography Specifications Version 2.2

https://tools.ietf.org/html/rfc8017

https://www.openssl.org/docs/man1.1.1/man1/openssl-rsa.html

PEM label ```-----BEGIN RSA PRIVATE KEY-----```

```asn1
RSAPrivateKey ::= SEQUENCE {
  version           Version,
  modulus           INTEGER,  -- n
  publicExponent    INTEGER,  -- e
  privateExponent   INTEGER,  -- d
  prime1            INTEGER,  -- p
  prime2            INTEGER,  -- q
  exponent1         INTEGER,  -- d mod (p-1)
  exponent2         INTEGER,  -- d mod (q-1)
  coefficient       INTEGER,  -- (inverse of q) mod p
  otherPrimeInfos   OtherPrimeInfos OPTIONAL
}
```  

## PKCS #5: Password-Based Cryptography Specification Version 2.1

v2.1: https://tools.ietf.org/html/rfc8018

## PKCS #8: Private-Key Information Syntax Specification Version 1.2

Proposed: https://tools.ietf.org/html/rfc5958

v1.2: https://tools.ietf.org/html/rfc5208

https://en.wikipedia.org/wiki/PKCS_8

https://www.openssl.org/docs/man1.1.1/man1/openssl-pkcs8.html

PEM label ```-----BEGIN ENCRYPTED PRIVATE KEY-----```
or ```-----BEGIN PRIVATE KEY-----```

```asn1
AlgorithmIdentifier, ALGORITHM-IDENTIFIER
  FROM PKCS-5 {iso(1) member-body(2) us(840) rsadsi(113549)
  pkcs(1) pkcs-5(5) modules(16) pkcs-5(1)};
         
EncryptedPrivateKeyInfo ::= SEQUENCE {
  encryptionAlgorithm  EncryptionAlgorithmIdentifier,
  encryptedData        EncryptedData }

EncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

EncryptedData ::= OCTET STRING
```

> encryptionAlgorithm identifies the algorithm under which the private-key information is encrypted.  Two examples are PKCS #5's pbeWithMD2AndDES-CBC and pbeWithMD5AndDES-CBC [PKCS#5].

> encryptedData is the result of encrypting the private-key information.

## PKCS #12

v1.1: https://tools.ietf.org/html/rfc7292

https://en.wikipedia.org/wiki/PKCS_12

```asn1
PrivateKeyInfo, EncryptedPrivateKeyInfo
  FROM PKCS-8 {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1)
              pkcs-8(8) modules(1) pkcs-8(1)}

PKCS8ShroudedKeyBag ::= EncryptedPrivateKeyInfo
```
