# Attacks against Hohha Dynamic XOR

Here will be a collection of examples demonstrating attacks against the Hohha
Dynamic XOR encryption algorithm.

## Adaptive CPA2 and CCA2

Chosen plain text (CPA) and chosen cipher text (CCA) attacks are equivalent
against this algorithm.  In other words, a method of attack using chosen plain
text is just as effective with chosen cipher text.  In any of the oracles for
CCA or CPA attacks, just change encryption `-e` to decryption `-d` or vice
versa, and the attack will still succeed.

For CPA or CCA attacks, the adversary is able to send plain text messages to be
encrypted, and receive the encrypted result, or vice versa.  The adversary is
not allowed to see the key or observe the operation of the algorithm.  The
adversary may only observe the result.  The adversary is only allowed to use
one operation, either encryption or decryption, not both.

In CPA attacks, the adversary gets to choose the plain text.  It is possible
that the adversary gets to choose the salt, too, but more likely the salt will
not be under control of the adversary.  It is still interesting to consider the
strength of the algorithm when the adversary can choose the salt.

In CCA attacks, the adversary gets to choose the cipher text.  Since the salt
and cipher text would be transferred in the same message, and the adversary can
choose the cipher text, it is realistic to assume that the adversary can affect
all parts of the message, including the salt.

### Key Recovery: Key Length

The key length is supposed to be secret information.  A CCA2 attack is
provided which will recover the key length.

```
# choose a secret key
vi oracle-length.sh

# recover the key length with CCA2
./solve-length.py
```

### Key Recovery: Key Jumps

The key number of jumps is supposed to be secret information.  A CCA2 attack is
provided which will recover the key number of jumps, up to 46 jumps.

```
# choose a secret key
vi oracle-jumps.sh

# recover the key jumps with CCA2
./solve-jumps.py
```

### Plain Text Recovery

Given an encrypted message, the plain text of the message is supposed to be
secret information.  A CPA2 attack is provided which will recover the plain
text.  The CPA2 attack is not allowed to use decryption, otherwise recovering
the encrypted message would be trivial (decrypt it).  Instead, the CPA2 attack
will use information leaked by the encryption function to recover the encrypted
message.

Note: this is a CPA2 attack, and the adversary also chooses the salt.

```
# choose a secret key
vi oracle-msg.sh

# generate a random salt
S=$(../scripts/gensalt.py)
# this is your salt
echo "$S"

# encrypt the message
C=$(./oracle-msg.sh -S "$S" -M "attack at midnight")
# this is your cipher text
echo "$C"

# recover the secret message
./solve-msg.py "$S" "$C" | base64 -d; echo
```

### Cipher Text Forgery

Given a plain text, only the owner of the key should be able to reliably
produce a valid cipher text that contains the message.  The CCA2 attack is
equivalent to the CPA2 plain text recovery attack, except that it uses
information leaked by the decryption function to produce a valid encrypted
message.

A separate attack is not provided for cipher text forgery.  To perform cipher
text forgery, change the operation of oracle in the plain text recovery attack
to decryption.  Then the attack becomes CCA2 cipher text forgery.

```
# choose a secret key, change method to decrypt
vi oracle-msg.sh

# generate a random salt
S=$(../scripts/gensalt.py)
# this is your salt
echo "$S"

# encode the false secret message
M=$(echo -n "retreat at dusk" | base64)
# this is your base64 plain text
echo "$M"

# forge a ciphertext
C=$(./solve-msg.py "$S" "$M")
# this is your ciphertext
echo "$C"

# decrypt the ciphertext
T=$(./oracle-msg.sh -S "$S" -m "$C")
# this should match your base64 plain text
echo "$T"
# and this is your secret message
echo "$T" | base64 -d; echo
```
