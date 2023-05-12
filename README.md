# The Argon Standard Library
This is the official repository of Argon's standard libraries.

The modules here are mostly native components (written in C++) that offer access to system services, but also modules that wrap third-party libraries to offer particular functionality (such as regex).

Also there are Argon modules that provide standard solutions for various problems that can occur in everyday programming.

## 🚧 Structure

The components of each module (native code, Argon code, etc.) must be located in a folder represented by the name of the module, suitably exposed to `cmake` by adding it to the main project file.

To give a sense of unity, the version of each single module is given by the version of the standard library (for this purpose you can include and use the version macros present in the `version.h` header). 

In any case, if necessary, it is possible to use a customized version for a given module.

## 🪄 Current modules

- Networking and IC:
  - ssl 
- Text processing:
  - regex
