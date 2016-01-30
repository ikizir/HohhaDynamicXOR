# HohhaDynamicXOR

This is a C implementation of Hohha Dynamic XOR algorithm.


## Description

Hohha Dynamic XOR is a new symmetric encryption algorithm developed for Hohha Secure Instant Messaging Platform and opened to the public via dual licence MIT and GPL.

The essential logic of the algorithm is using the key as a "jump table" which is dynamically updated with every "jump".

Check out our **[Wiki]** for more information.


## Compilation

```
gcc -O3 -Wall -o test HohhaDynamicXOR.c
./test
```
Will run the integrity checks, and print out the benchmarks.


## Contacts

Ismail Kizir <[ikizir@gmail.com]>

[wiki]: https://github.com/ikizir/HohhaDynamicXOR/wiki
[ikizir@gmail.com]: mailto:ikizir@gmail.com

## Third party implementations

These are unofficial implementations by 3rd party developers.

Javascript: https://github.com/ed770878/hohha-js : The author hasn't implemented Hohha Communication Format. We don't recommend using it for real life applications.
