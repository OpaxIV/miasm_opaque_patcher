# Miasm Opaque Predicate Patching Script
A Miasm Python Script capable of patching Opaque Predicates in ELF and PE Binaries.

## About
Miasm's Python API does not have the functionality to load an ELF binaries at the time of writing. Only PE executables are currently supported. Due to this limitation, during a task I had to analyse an ELF binary, which contained a vast amount of opaque predicates. To automate this process by removing all the opques, I wrote this script to help me doing so.

## Requirements
It is recommended to use a Python virtual environment.

* Miasm: https://github.com/cea-sec/miasm
* Z3: https://github.com/Z3Prover/z3
