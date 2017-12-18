## Disclaimer & License

I am not a cryptographer or cryptocurrency expert.  As such, the code here 
might have serious flaws, mistakes, or errors that could result in the loss
of your cryptocurrency.  The code is provided as-is.  

Use this code at your own risk.

The code provided is released under the MIT license:

Copyright (c) 2017 Jake B.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

** You should probably know what you're doing before trying to use these
scripts**

## Support this Project

Support this project by sending some BURST to: **BURST-ZGEK-VQ86-M9FV-7SDWY**

In fact, this address was created and public key announced using 
transactions made and signed using these scripts.  My hope is to 
eventually get the signing portion of this script handled by a hardware
wallet such as the Ledger Nano S. I'm currently using my "production"
Ledger, but probably should have one specifically for development.

## Description

This code is intended as a project to explore cryptocurrency.  The main
cryptocurrencies are too expensvie to really tinker with and BURST's proof
of capacity strategy is compelling.  

This script allows you to create new addresses, create and sign 
transactions, and broadcast transactions to the network.

It is intended as the beginning of a hot/cold wallet system.  Using these
scripts, you can:

	1.  Generate a new public/private keypair and address for a new
	wallet.  This can be done offline (ideally on a secure, air-gapped 
	computer). The private key and keyphrase need not leave the secure
	machine.

	2.  Transmit the public key to an online computer and use the script
	to generate a transaction for the new address.  Access to an online
	wallet is needed to retreive information about the blockchain to craft
	the unsigned transaction.

	3.  Transmit the unsigned transaction back to the secure air-gapped
	computer to apply the signature.

	4.  Transmit the signed tranaction back to a connected machine and
	broadcast the transaction it to the Burstcoin network.

