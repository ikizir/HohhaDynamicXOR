#!/bin/bash
PROGR=../HohhaHarness

# Usage: call just like hohha, without specifying the operation or key.
# Eg: oracle.sh -S <salt> -m <base64msg>
#
# The oracle will encrypt the message and reveal the ciphertext.  The oracle
# does not reveal the key.  The challenge is to decrypt a message.

# ONLY THE ORACLE has access to the secret.  NO PEEKING!

#K='BBAAIx73UyeYd2ofmK6ZR0fYa42sHGm0Ab2w'

# length 32
#K='BCAASUZ+J+EsY3EHCceySNhUsQPKmntdq6SkAKk6e7UVRPIXpFxk8z8amw=='

# length 64
#K='BEAAzUpxjQbJ3kUl7YgXPT6Km3CHDZrWYzyCRXpZ1y3qm2C1R6Z6AD+FkvWzcoDS2yvtNdXIuwSG7Su2+8HGM6XIN83BT1jUpaeI'

# length 128
K='BIAAc9GHQ4A4lWmzavQ5TkazAxRogJFvDLhUQ7Q7bjWfryImzZ//TxOhyAYqosRCv7gwG13iLOOlqOWJ8Esvj8bd/TPQ4Qvf2scOTkBNk3ikjLqgDnTjXyoGK0uYVu4G70PjHj2S+iDNG9/yPt1vJkLISyU4I/cWJoZbvVOXpTZx+mfb7AkkGeVGrA=='

# length 256
#K='BAABjguCiUefnypQ9tbDxtkIKcNYteGLlG7GXwUaIHrFiUTrjxQw0SEQZUJviQLSWONo/MwcfvgB72Rx7elx7wUPi2LMGDIIx2mv5oFOPybf5at4lD4c1KKPpQd4De3CKOtw+VCpC4IXLcUCvVoOmwMnFGhj3R0Ik5SmJ0p/n2mev3XCV5cLoXHVOB5wEgsiL4SOtbDMAvr9S6EWeUqg76TokC+zzzs3Adj4dEMp2H3UVboATmyjzxait+bQHjpXg9E3tOT++X5xZ9tXmlfesy4lVCNHkci/Qx0TQ+sHLBcFSMzhbk2bQ3J+MOIm3erzyI3Rxse92CwWnqgW0TMWo1q/XLAmm0SYkJRm'

"$PROGR" -e -K "$K" "$@"
