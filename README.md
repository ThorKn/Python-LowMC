# Python-LowMC
LowMC (Low Multiplicative Complexity) is a blockcipher.
The reference implementation is in C++ under MIT licence and can be found here:

[LowMC Github](https://github.com/LowMC/lowmc)

The LowMC paper is available at:

[LowMC paper](https://eprint.iacr.org/2016/687.pdf)

The files in this Repository (Python-LowMC) are a Python re-implementation of LowMC for usage with the Picnic Post-quantum signature algorithm. The Picnic reference implementation is in C under MIT license and can be found here:

[Picnic Github](https://github.com/Microsoft/Picnic)

The Picnic paper is available at:

[Picnic paper](https://microsoft.github.io/Picnic/)

## Prerequisites

* Python3 (tested with 3.6)
* Additional package: BitVector

It's recommended to use a Python virtual environment like ```virtualenv```. The BitVector package can be installed with 
``` 
pip install BitVector 
```
## Usage
#### Constants and matrices
LowMC needs pre-calculated constants and matrices. Therefore the python-file ```generator.py``` is included. The generator creates ```picnic-<x>.dat``` files with ```<x>``` beeing the security level L1, L2 or L3. There are three pre-calculated files contained in this repository. They can be used for the tests without generating them. 

If you wish to generate them for yourself, execute 
```
generator.py <arg>
```
with ```<arg>``` beeing one of the parameters ```picnic-L1```, ```picnic-L2``` or ```picnic-L3```. 
For the detailed parameter sets of each security level see the Picnic paper (Link above).
#### Tests
To run the tests with the Picnic-testvectors, simply execute
```
test_lowmc.py
```
There are 9 testvectors included. Three for each security level. They are taken from the Picnic reference implementation (Link above).
