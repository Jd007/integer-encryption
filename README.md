#### Integer to String Encoder and Decoder

Given a 32-bit integer, the encoder returns a 22-character URL-safe string that encrypts the integer within, which can be safely passed around in public without anybody knowing what the number is. The decoder returns the original integer given the encoded value.

A secret key is used, must be kept safe for the encrypted value to be secure, and the same key must be used by the encoder and decoder to function properly.

Requirements:
* Python hashlib and base64 (both part of standard lib)

Can be adapted to work with negative and 64-bit integers (the encoded str might be longer).

Based on the PHP integer ID obfuscation algorithm described here: http://raymorgan.net/web-development/how-to-obfuscate-integer-ids/