PKCS11 implementation for keys of pyca/cryptography
===================================================

``cryptography`` is a package which provides cryptographic recipes and
primitives to Python developers. Their goal is for it to be your "cryptographic
standard library".

This library uses ``PyKCS11`` to implement comunication to the ``PKCS11`` device (smartcard,...). 
As PKCS11 devices need an open session to work with them, this library provides 
context managers to execute tasks provided by pyca/cryptography. ``PKCS11KeySession`` is the 
context manager that will facilitate the use of implemented keys.

Context managers take information to connect to the ``PKCS11`` device (library, token label and 
key label, if there are more that one private keys on a token). Within the ``with`` statement 
the cryptographic operations with the key are made.

The ``PKCS11KeySession`` context meneager will return private key object of the type referenced by
library, token label and in some cases key label written on the ``PKCS11`` device. From private key 
public key can be retrieved like in pyca/cryptography and also certificates (and even CA chain)
(this is the extension ``PKCS11`` device tokens can provide).

This library provides keys for EC and RSA keys which are most comonly used keys on ``PKCS11`` devices.


