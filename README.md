Cryptopals
==========

> *Let us speak no more of faith in man, but bind him down from mischief by the chains of cryptography.*

My solutions to the [~~Matasano~~ Cryptopals Crypto Challenges](https://cryptopals.com/) in Python 3.

Test with `make test` and generate a test coverage report with `make coverage`.

Set 1: Basics
-------------

1. [x] [Convert hex to base64](m01.py)
2. [x] [Fixed XOR](m02.py)
3. [x] [Single-byte XOR cipher](m03.py)
4. [x] [Detect single-character XOR](m04.py)
5. [x] [Implement repeating-key XOR](m05.py)
6. [x] [Break repeating-key XOR](m06.py)
7. [x] [AES in ECB mode](m07.py)
8. [x] [Detect AES in ECB mode](m08.py)

Set 2: Block crypto
-------------------

9. [x] [Implement PKCS#7 padding](m09.py)
10. [x] [Implement CBC mode ](m10.py)
11. [x] [An ECB/CBC detection oracle](m11.py)
12. [x] [Byte-at-a-time ECB decryption (Simple)](m12.py)
13. [x] [ECB cut-and-paste](m13.py)
14. [x] [Byte-at-a-time ECB decryption (Harder)](m14.py)
15. [x] [PKCS#7 padding validation](m15.py)
16. [x] [CBC bitflipping attacks](m16.py)

Set 3: Block and stream crypto
----------------------------

17. [x] [The CBC padding oracle](m17.py)
18. [x] [Implement CTR, the stream cipher mode](m18.py)
19. [x] [Break fixed-nonce CTR mode using substitutions](m19.py)
20. [x] [Break fixed-nonce CTR statistically](m20.py)
21. [x] [Implement the MT19937 Mersenne Twister RNG](m21.py)
22. [x] [Crack an MT19937 seed](m22.py)
23. [x] [Clone an MT19937 RNG from its output](m23.py)
24. [x] [Create the MT19937 stream cipher and break it](m24.py)

Set 4: Stream crypto and randomness
-----------------------------------

25. [x] [Break "random access read/write" AES CTR](m25.py)
26. [x] [CTR bitflipping](m26.py)
27. [x] [Recover the key from CBC with IV = Key](m27.py)
28. [x] [Implement a SHA-1 keyed MAC](m28.py)
29. [x] [Break a SHA-1 keyed MAC using length extension](m29.py)
30. [x] [Break an MD4 keyed MAC using length extension](m30.py)
31. [x] [Implement and break HMAC-SHA1 with an artificial timing leak](m31.py)
32. [x] [Break HMAC-SHA1 with a slightly less artificial timing leak](m32.py)

Set 5: Diffie-Hellman and friends
---------------------------------

33. [x] [Implement Diffie-Hellman](m33.py)
34. [x] [Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](m34.py)
35. [x] [Implement DH with negotiated groups, and break with malicious _g_ parameters](m35.py)
36. [x] [Implement Secure Remote Password (SRP)](m36.py)
37. [x] [Break SRP with a zero key](m37.py)
38. [x] [Offline dictionary attack on simplified SRP](m38.py)
39. [x] [Implement RSA](m39.py)
40. [x] [Implement an _e_ = 3 RSA broadcast attack](m40.py)

Set 6: RSA and DSA
------------------

41. [x] [Implement unpadded message recovery oracle](m41.py)
42. [x] [Bleichenbacher's _e_ = 3 RSA Attack](m42.py)
43. [x] [DSA key recovery from nonce](m43.py)
44. [x] [DSA nonce recovery from repeated nonce](m44.py)
45. [x] [DSA parameter tampering](m45.py)
46. [ ] RSA parity oracle
47. [ ] Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)
48. [ ] Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

Set 7: Hashes
-------------

49. [ ] CBC-MAC Message Forgery
50. [ ] Hashing with CBC-MAC
51. [ ] Compression Ratio Side-Channel Attacks
52. [ ] Iterated Hash Function Multicollisions
53. [ ] Kelsey and Schneier's Expandable Messages
54. [ ] Kelsey and Kohno's Nostradamus Attack
55. [ ] MD4 Collisions
56. [ ] RC4 Single-Byte Biases

Set 8: Abstract algebra
-----------------------

57. [ ] Diffie-Hellman Revisited: Small Subgroup Confinement
58. [ ] Pollard's Method for Catching Kangaroos
59. [ ] Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
60. [ ] Single-Coordinate Ladders and Insecure Twists
61. [ ] Duplicate-Signature Key Selection in ECDSA (and RSA)
62. [ ] Key-Recovery Attacks on ECDSA with Biased Nonces
63. [ ] Key-Recovery Attacks on GCM with Repeated Nonces
64. [ ] Key-Recovery Attacks on GCM with a Truncated MAC

