#!/usr/bin/env python3
# Copyright (c) 2017 Jake B.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

#############################################################################
# Support this project by sending some BURST to: BURST-ZGEK-VQ86-M9FV-7SDWY #
#############################################################################
# From standard library
import hashlib
import struct
import sys
from datetime import datetime, timedelta, timezone
from io import BytesIO

# Local stuff
import curve25519
from nxt_address import NxtAddress
from passphrase import generatePassPhrase
import transaction

# Some constants
ONE_NXT = 100000000
EPOCH_BEGINNING = datetime(2014, 8, 11, 2, 0, 0, 0)

# This will take a timestamp in the BURST blockchain epoch format
# and convert it to a standard datetime
def convertFromEpochTime(theTime):
	time = EPOCH_BEGINNING + timedelta(seconds=theTime)
	return time.replace(tzinfo=timezone.utc).astimezone(tz=None)

# This will take a standard date time and return a timetsamp int he
# BURST blockchain format
def convertToEpochTime(theTime):
	diff = (theTime.replace(tzinfo=None) - EPOCH_BEGINNING)
	return int(((diff.days * 86400000) + (diff.seconds * 1000) + (diff.microseconds / 1000)) / 1000)

# Return the current time in the BURST Blockchain epoch format
def getEpochTime():
	return convertToEpochTime(datetime.now(timezone.utc))

# This is a class designed to handle the itneraction with an online wallet API
class OnlineWallet:
	def __init__(self, baseWalletUrl):
		self.base = baseWalletUrl

	# Get economic clustering information
	def getECBlockInfo(self):
		a = [('requestType','getECBlock')]
		params = urllib.parse.urlencode(a)
		request_url = self.base + "?" + params
		result = json.loads(urllib.request.urlopen(request_url).read())
		return (result['ecBlockHeight'], result['ecBlockId'])

	# Get information about a wallet
	def getWallet(self, wallet):
		a = (('requestType','getAccount'),('account', wallet))
		params = urllib.parse.urlencode(a)
		request_url = self.base + "?" + params
		result = json.loads(urllib.request.urlopen(request_url).read())
		return result

	# Get wallet balance
	def getWalletBalance(self, wallet):
		return float(getWallet(wallet)['balanceNQT']) / ONE_NXT

	# Get wallet public key
	def getWalletPublicKey(self, wallet):
		return getWallet(wallet)['publicKey']

	# Broadcast transaction to the network
	def broadcastTransaction(self, hexData):
		a = [('requestType','broadcastTransaction'), ('transactionBytes', hexData)]
		params = urllib.parse.urlencode(a)
		request_url = self.base
		result = json.loads(urllib.request.urlopen(request_url, params.encode('ascii')).read())
		return result

# This function outlines the workflow for creating a new wallet address.
# It does not require a connection to a wallet API, and can be run from a cold-wallet machine
def generateNewWallet():
	passphrase = generatePassPhrase();
	print("This application will generate a new BURST keypair and address.")
	print("This is done completely offline without accessing the BURST network.")
	print("")
	print("Your new passprhase is: \n\t" + passphrase + "\n")
	print("Please write down your passphrase and store it securely.")
	print("Do not keep your passphrase on another computer, phone, or digital device.")
	print("Do not enter your passphrase into an online wallet, as it may be exposed.")
	print("")
	confirm = input("Please re-enter your passprhase.  Do not cut/copy:")

	if confirm.upper() != passphrase.upper():
		print("ERROR: passphrases do not match")
		return

	secret = hashlib.sha256(passphrase.lower().encode('ascii')).digest()

	verification_key, signing_key, secret_clamped = curve25519.curve25519_eckcdsa_keygen(secret)

	print("Private Key:     ", signing_key.hex())
	print("Public Key:      ", verification_key.hex())

	pk_hash = hashlib.sha256(verification_key).digest()	
	numeric = struct.unpack("<Q", pk_hash[0:8])[0]
	print("Numeric Account: ", numeric)

	x = NxtAddress()
	x.set(numeric)
	print("Address        : ", x.toString())
	print("")
	print("Remember to save both the address AND the public key for use in your first transaction.")

# This function outlines the workflow for signing an exsiting unsigned transaction
# It does not require a connection to a wallet API, and can be run from a cold-wallet machine
def signTransaction():
	filename = input("Enter filename of hex-encoded transaction (blank to enter directly): ")
	data = None
	if (len(filename) == 0):
		data = input("Enter HEX: ")
	else:
		with open(filename, 'rb') as f:
			data = f.read()
			f.close()

	transaction_bytes = bytes.fromhex(data.decode('ascii'))

	passphrase = input("Enter passhrase of sending account: ")
	if (len(passphrase) == 0):
		print("No passphrase provided for signing")
		return

	transaction_obj = transaction.readTransactionData(BytesIO(transaction_bytes))
	secret = hashlib.sha256(passphrase.lower().encode('ascii')).digest()

	verification_key, signing_key, secret_clamped = curve25519.curve25519_eckcdsa_keygen(secret)
	if (transaction_obj['senderPublicKey'] != verification_key):
		print("Public keys do not match")
		return

	signature = curve25519.kcdsa_sign(transaction_bytes, secret)
	
	transaction_obj['signature'] = signature

	write_bytes = transaction.transactionToBytes(transaction_obj)
	filename = input("Enter filename to write hex-encoded signed transaction (blank to print to screen):")
	if (len(filename) == 0):
		print(write_bytes.hex())
	else:
		with open(filename, 'wb') as f:
			f.write(write_bytes.hex().encode('ascii'))
			f.close()

# This function outlines the workflow for creating an unsigned transaction
# It does require a connection to a wallet API to lookup account and blockchain information.
def makeTransaction(wallet):
	send_addr= input("Please enter sending address: [BURST-xxxx-xxxx-xxxx-xxxxx]: ")
	if (len(send_addr) == 0):
		print("No source address provided")
		return

	send_acct = wallet.getWallet(send_addr)
	if (send_acct == None or ('errorCode' in send_acct and send_acct['errorCode'] == 5)):
		print("Could not find source account in blockchain.")
		return

	send_balance = float(send_acct['balanceNQT']) / ONE_NXT
	if ('publicKey' in send_acct):
		send_pub_key = send_acct['publicKey']
	else:
		# Public key is not on the blockchain.  Perhaps a new account.  Need to be provided
		# public key directly.
		send_pub_key = input("Enter public key for new account: ")

	print("Sender Address:   ", send_addr)
	print("Sender Account:   ", send_acct['account'])
	print("Sender Balance:   ", send_balance)
	print("Sender PublicKey: ", send_pub_key)

	if (send_balance <= 0):
		print("Insufficient funds to send")
		return

	dest_addr = input("Please enter destination address [BURST-xxxx-xxxx-xxxx-xxxxx]: ")
	if (len(dest_addr) ==0):
		print("No destination address provided")
		return

	dest_acct = wallet.getWallet(dest_addr)
	if (dest_acct == None or  ('errorCode' in dest_acct and dest_acct['errorCode'] == 5)):
		print("Count not find desitnation account on the blockchain.  It may a new address.")
		x = NxtAddress()
		x.set(dest_addr)
		dest_acct_id = x.account_id()
	else:
		dest_balance = float(dest_acct['balanceNQT']) / ONE_NXT
		dest_acct_id = dest_acct['account']
		dest_pub_key = dest_acct['publicKey']	
		print("Dest Address:   ", dest_addr)		
		print("Dest Balance:   ", dest_balance)
		print("Dest PublicKey: ", dest_pub_key)
	print("Dest Account:   ", dest_acct_id)

	amount = int(input("Enter amount to send: "))
	if (amount < 0):
		print("Amount must be > 0")
		return

	ecBlockInfo = wallet.getECBlockInfo()

	transaction_obj = {'type'   : 0,
     		   'subtype': 0,
     		   'version': 1,
     		   'timestamp': getEpochTime(),
     		   'deadline': 1440,
               'senderPublicKey': bytearray.fromhex(send_pub_key), 
     		   'recipientId': int(dest_acct_id),
			   'amountNQT': amount * ONE_NXT,
			   'feeNQT': 1 * ONE_NXT,
			   'referencedTransactionFullHash': bytearray(('\0'*32).encode('ascii')),
			   'signature': bytearray(('\0'*64).encode('ascii')),
			   'flags': 0,
			   'ecBlockHeight': int(ecBlockInfo[0]),
			   'ecBlockId': int(ecBlockInfo[1]) }

	message = input("Enter an optional message: ")
	if (len(message) > 0):
		if len(message) > 255:
			print("message too long... ignorning")
		else:
			transaction_obj['message'] = bytes(message.encode('ascii'))

	transaction_bytes = transaction.transactionToBytes(transaction_obj)
	filename = input("Enter filename to save hex-encoded transaction data file (blank to print): ")
	if (len(filename) == 0):
		print(transaction_bytes.hex())
	else:
		with open(filename, 'wb') as f:
			f.write(transaction_bytes.hex().encode('ascii'))
			f.close
	
	return		

# This function outlines the workflow for broadcasting a signed transaction to the BURST network
# It does require a connection to a wallet API broadcast the transaction
def broadcastTransaction(wallet):
	filename = input("Enter filename with hex-ecoded signed transaction (blank to enter directly): ")
	data = None
	if (len(filename) == 0):
		data = input("Enter HEX:")
	else:
		with open(filename, 'rb') as f:
			data = f.read()
			f.close()

	response = wallet.broadcastTransaction(data)
	print(response)


if __name__ == "__main__":
	print("Please select a menu option below.\n")
	
	print("Offline options:")
	print("1. Generate new wallet address and passphrase.")
	print("2. Sign a transaction with a passphrase.")
	print("\nOnline options:")
	print("3. Create an unisgned transaction for signing later by an offline wallet")
	print("4. Broadcast a signed transaction to the BURST network")
	print("")
	option = int(input("Please enter an option: "))

	wallet = None
	if (option in [3,4]):
		# Online actions
		import urllib, urllib.request
		import json
		print("Select your online wallet: ")
		print("1. PoCC Production")
		print("2. PoCC Testnet")
		print("3. Enter URL")
		wallet_index = int(input("Please select a wallet provider: "))
		if (wallet_index == 1):
			wallet = OnlineWallet("https://wallet.burst.cryptoguru.org:8125/burst")
		elif (wallet_index == 2):
			wallet = OnlineWallet("http://176.9.47.157:6876/burst")
		elif (wallet_index == 3):
			print ("Provide the URL to the online wallet of choice.  For example https://wallet.burst.cryptoguru.org:8125/")
			url = input("Enter wallet URL: ")
			if not url.endswith("/burst"):
				if not url.endswith("/"):
					url += "/"
				url += "burst"
			wallet = OnlineWallet(url)
		else:
			print("Uknown wallet selected")
			sys.exit(1)

	if (option == 1):
		generateNewWallet()

	elif (option == 2):
		signTransaction()

	elif (option == 3):
		makeTransaction(wallet)

	elif (option == 4):
		broadcastTransaction(wallet)

	else:
		print("Unknown option. Exiting")
