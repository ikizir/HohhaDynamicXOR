#!/bin/bash
PROGR=../HohhaHarness

# Usage: call just like hohha, without specifying the operation or key.
# Eg: oracle.sh -S <salt> -m <base64msg>
#
# The oracle will decrypt the message and reveal the plaintext.  The oracle
# does not reveal the key.  The challenge is to learn something about the key,
# which is supposed to be secret, by observing the result of the decryption.

# ONLY THE ORACLE has access to the secret.  NO PEEKING!

# 2 jumps
#K='AkAAlFDsoXbaQ5JZzEj1UEFMXquxk7ozI0iELC9NbbpoKDxiSWOymem+tjV+5PlVHlhApMCu2TPFZuqOrjCXKT+LZ8L+EWFHwIPV'

# 3 jumps
#K='A0AAhffEzHMfPozY5N2QDQhRdIPYSERijzyixq52QAG8gBmFD6U5YuvrpEjEYrC1uoEXt1rOFC/ToLq1CLIqhxoYGQVw1ezTJy6J'

# 4 jumps
#K='BEAADBLmQM9ih3wJZfvBHMrIwE6HIn8iUsRDOv98r1l7ESSg8Ryw6fzCOxhcPuAXyWfPDyISor8KkRwvAtWbuh5yzdGN2OQ4GMTr'

# 13 jumps
#K='DUAA7EOqhHLY+lOz9MOBNl7eHIw8h9g4j/wQaqLbj/U8FCGGCPOYcB5hFCcxDhYu4flr8DBC8Q/H2gyyo9PX2Fv8o/CA4WEGdC+i'

# 42 jumps
#K='KkAAAbtJE/ioSy2IIHa53XkIwV3uDas+DTRFmwicn4F649iubNJ/NtZB3hyqWpOOW6jOah2ZoHDJf6gdOehGm8N0xVVqnnyw9vd8'

# 43 jumps
#K='K0AABr1IjHMOEUg6uIPxZ60pRjMpSC64aGF+Sxp0yNRdyThoQ1HcOUdVOObcHdI8oyw0SgpWeE+FtUZINf1ggyGOJDsMPsL2ldy7'

# 44 jumps
#K='LEAAyWGHpojMZadQFCIQCWZ2oT5Y1XhU61OMk7ZSiQnkd8eR9BPuZY0yDplXERUC78KRTUYbkQprRF89omQaW7hwuSp5MXFV5TWJ'

# 45 jumps
#K='LUAAqf9m3mZ5D7vMAWmVJorRVkJeJXFMLPfEMDm8r837Q7XkSKxw+BkcgmtLg89SZdTva1oXMBIOM0kgML+wmsW3csMm8T6LdT0x'

# 46 jumps
K='LkAAQ8zfHWdE8EaQQwlAEKX03R9S7lsaCu7dlux9oJvu8sSRAoljixfnfw0pN1IhuZsW9yvrYnlW5InNwepSZBEIBbZNUAzolWbn'

# things start to fall apart around here... when s2 finally rolls over

# 47 jumps
#K='L0AAEuuPitBYKrFMXSzxqvcFB2EXVYt5s3nHr3Fd+MolUN/lW9KUOLsQ+AT4OCineVWlBhXWeAtdDMfV2F3artvmRMPaV0eOR9aK'

# 48 jumps
#K='MEAAkPtavHykFeMDAe0O1jRl2i9oXVvfFjSnJP6sE5UHfVH7Ywqeji3CIgwyvw+4Fir7Kr/4Bv8frPJhTp0qKSty7TMOv7GX4xUj'

# 49 jumps
#K='MUAAlDYRs3LyCiJicJBAl5IGswt6BiD6p7RHwcz99KgWg8iR+JrMBx1Dex7Zb/qD05KxCoEmk5BmRQ2sUEV8eeiY8Nrqjr3sdLlq'

# 50 jumps
#K='MkAAbhSNWRMXWtje5L4cTxDRXxqS1a/fOyZs1AHY2vN4yqvrYsTxurDtajvsCzugLjQiRLvXHmiRcjgI1Gx5tSpcybUmYCWkVlAl'

"$PROGR" -d -K "$K" "$@"
