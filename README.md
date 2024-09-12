# The Argon Standard Library
This is the official repository of Argon's standard libraries.

The modules here are mostly native components (written in C++) that offer access to system services, but also modules that wrap third-party libraries to offer particular functionality (such as regex).

Also there are Argon modules that provide standard solutions for various problems that can occur in everyday programming.

## 🚧 Structure

The components of each module (native code, Argon code, etc.) must be located in a folder represented by the name of the module, suitably exposed to `cmake` by adding it to the main project file.

To give a sense of unity, the version of each single module is given by the version of the standard library (for this purpose you can include and use the version macros present in the `version.h` header). 

In any case, if necessary, it is possible to use a customized version for a given module.

## 🪄 Current modules

- Concurrent Execution:
  - syncutil -- Utilities and primitives for synchronization and concurrency control
- Cryptographic Services:
  - hashlib -- Secure hashes and message digests
- Data Compression and Archiving:
  - zipfile -- Read and write ZIP-format archive files
  - lzma -- Compression using the LZMA algorithm
  - bz2 -- Compression compatible with bzip2
  - zlib -- Compression compatible with gzip
- Data Types:
  - enum -- Provides a set of algorithms to work with enumerables
- Development Tools:
  - unittest -- Unit testing framework
- File formats:
  - ini -- INI format parser
- Internet protocols and related stuff:
  - base64 -- Base16, Base32, Base64 data encodings
  - http -- HTTP modules 
  - json -- JSON encoder and decoder
  - url -- URL handling module
- Language utilities:
  - argparse -- Parser for command-line options
- Networking and IC:
  - ssl -- SSL/TLS wrapper for socket objects
- Numeric and math-related functions:
  - random -- Generate pseudo-random numbers
- Operating system services:
  - ospath -- Common pathname manipulations
  - subprocess -- Initiating and managing processes
- Text processing:
  - regex -- Perl-like regex support
