# Project One - AES
Skeleton solution with build guidelines.

## Building
`mkdir P1/build && cd P1/build && cmake ..`

## Installing (Linux)
You can install the output shared object `libaes.so` to
enable dynamic linking for other system objects. You can
do the same for the test cli tool, `aes-cli`, such that
it is placed in your PATH. Simply run: `sudo make install`

## Notes & Recommendations
It is highly recommended to use the provided Vagrant
development solution. It provides an "it just works"
environment for building your project consistently.

If you do not use Vagrant, you will need to install the
requisite packages on your own. In theory, you can
build this solution from MacOS. However, neither
MacOS or Windows are officially supported. Note that
the CI solution will execute tests in a Linux environment.

