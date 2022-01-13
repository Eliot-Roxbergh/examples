Here is a quick summary for elliptic curve cryptography with emphasis on Edwards curves.


# Elliptic Curve Cryptography (ECC)

The ECC is commonly used in TLS and Bitcoin, etc. ... in favor of RSA. So called public-key (i.e. asymmetric) cryptography

Unlike RSA, ECC is not used for encryption, only for signing (and key exchange).
Still, ECC is useful and e.g. we may use Elliptic Curve Diffie-Hellman (ECDH) for key-exchange (with ephemeral keys) in TLS 1.3 to agree on a session (symmetric) key.

Neither ECC or RSA is quantum safe. For quantum safe crypto see other algorithms such as LATTICE.

EC keys are much shorter than RSA, while maintaining the same or better security (see "security bits").

Edwards curves is a type of EC.

## ECC Signing (simplified)

### Intuition (simplified, might be wrong on the details)

We have a curve (mod q, so we loop back after a while).

A known starting point G.

A private key x which is an integer.
By taking xG we get to the point U which is the public key.


Addition, is defined as taking the tangent between two points, which yields a third point on the curve, and then negating this new point.
		"addition is defined as the negation of the point resulting from the intersection of the curve"

Doubling, like addition but instead of tangent between two points we take the derivate of a single point ... which yields a new point on the curve.

Multiplication, is possible by performing addition repeatedly.
Moreover, multiplication with large numbers is also fast since we can double and perform addition as necessary to reach the desired multiplicator.
Multiplication makes it easy to from the private key (x), get the public key (U=xG).

However, the security of ECC depends on the difficulty to do the opposite, i.e. perform division.
    (something like x = U/G or whatever, is not directly doable)
Of course, a bruteforce approach would be possible, where addition is performed until a match is found ( G+G+G+..+G = U )
[1]

......

### How to Make an EC Signature (simplified)

Publically known: we have a curve E, a point on this curve G, an a large prime number q used for modulus).
The signature (s,r) is of course sent and readable by anyone, who may (by using the public key) verify it

Variables:
    k is a random value mod q (a nonce, the randomness of k is very important)

    h = "data to sign" mod q (converted with bits2int)

Signature is the tuple of two large integers (s, r):

    r = [x-coordinate of kG mod q]

    s = (h+x*r)/k mod q
        =>
    [simplified]
    s = (data to sign + private key + "random point in group's x-coordinate")/"random int" (mod q)

[2]

#### Quick Comparision with Edward Curves

    (R = rG ... so a public key point for this signature)

    h = hash(R + pubKey + msg) mod q

    r = (hash(hash(privKey) + msg) mod q)*G

    s = (r + h * privKey) mod q

[3]

##### NOTE on edward curves:

Private key (is also an integer "nr of jumps") and public keys (here it is also point but compressed to a single integer) are similar to regular ECC but with some extra manipulations:

Private key:
"The seed is first hashed, then the last few bits, corresponding to the curve cofactor (8 for Ed25519 and 4 for X448) are cleared, then the highest bit is cleared and the second highest bit is set.".
Because: "These transformations guarantee that the private key will always belong to the same subgroup of EC points on the curve and that the private keys will always have similar bit length (to protect from timing-based side-channel attacks)." [3]

Public key:
"The public key is encoded as compressed EC point: the y-coordinate, combined with the lowest bit (the parity) of the x-coordinate." [3]


### Comment

Usually the data to be signed is hashed prior, and with a hash algorithm (message digest) equal or slightly smaller than the "key length" q.
("hlen is roughly equal to qlen, since the overall security of the signature scheme will depend on the smallest of hlen and qlen")

e.g.
ECDSA256 -> sha256
ECDSA521 -> sha512

### Questions

Is padding used? Is it important, and which padding?
	    Well it's not in the RFC, and the message seems to always be hashed (what does e.g. the OpenSSL implementation do?)
		At least edwards curves ed448 and 25519 mandates a certain hash algo and the message hashed accordingly.
            Also never used for encryption, which makes padding "less important" ?

[1] - <https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication>

[2] - RFC6979 (<https://datatracker.ietf.org/doc/html/rfc6979>)

[3] - <https://cryptobook.nakov.com/digital-signatures/eddsa-and-ed25519>


## Edward is a subset of ECC

"In 2007, Harold Edwards introduced a new form for elliptic curves. Thereafter, people interestingly named this form as Edwards Curves" [1]

with special characteristic ...

More in RFC7748, RFC8032 (<https://datatracker.ietf.org/doc/html/rfc7748>, <https://datatracker.ietf.org/doc/html/rfc8032>)


Addition and doubling is easy.
Unlike ECC it doesn't use a tangent line or similar.. regardless we may add two points and we get a new point on the edward curve [1].

In the same manner, pubKey = privKey * G

### Summary

See earlier section [#quick-comparision-with-edward-curves](#quick-comparision-with-edward-curves), but also

    "Private key:
    	The private key is generated from a random integer, known as seed (which should have similar bit length, like the curve order). The seed is first hashed, then the last few bits, corresponding to the curve cofactor (8 for Ed25519 and 4 for X448) are cleared, then the highest bit is cleared and the second highest bit is set. These transformations guarantee that the private key will always belong to the same subgroup of EC points on the curve and that the private keys will always have similar bit length


    Public key:
    	The public key pubKey is a point on the elliptic curve, calculated by the EC point multiplication: pubKey = privKey * G (the private key, multiplied by the generator point G for the curve). The public key is encoded as compressed EC point: the y-coordinate, combined with the lowest bit (the parity) of the x-coordinate

    Sign:
	    Calculate pubKey = privKey * G
	    Deterministically generate a secret integer r = hash(hash(privKey) + msg) mod q (this is a bit simplified)
	    Calculate the public key point behind r by multiplying it by the curve generator: R = r * G
	    Calculate h = hash(R + pubKey + msg) mod q
	    Calculate s = (r + h * privKey) mod q
	    Return the signature { R, s }

    Verify:
	    Calculate h = hash(R + pubKey + msg) mod q
	    Calculate P1 = s * G
	    Calculate P2 = R + h * pubKey
	    Return P1 == P2"

from <https://cryptobook.nakov.com/digital-signatures/eddsa-and-ed25519> ([2])

### Comment:

   _"Signing with Ed25519 uses SHA-512 as part of the signing operation,
   and signing with Ed448 uses SHAKE256 as part of the signing
   operation."_ - RFC8419

[1] - <https://sefiks.com/2018/12/19/a-gentle-introduction-to-edwards-curves/>

[2] - <https://cryptobook.nakov.com/digital-signatures/eddsa-and-ed25519>
