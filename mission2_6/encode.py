from Crypto import Random
from Crypto.PublicKey import RSA
import base64
import sys

#def generate_keys():
#      	modulus_length = 256*4
#   	privatekey = RSA.generate(modulus_length, Random.new().read)
#	publickey = privatekey.publickey()
#	return privatekey, publickey

def encrypt_message(a_message , publickey):
	encrypted_msg = publickey.encrypt(a_message, 32)[0]
	encoded_encrypted_msg = base64.b64encode(encrypted_msg)
	print(encoded_encrypted_msg)
	return encoded_encrypted_msg

def main(arg):
	a_message = arg
	publickey = RSA.importKey(open("public_pem.pem", "rb"))
	encrypt_msg = encrypt_message(a_message, publickey)
	return encrypt_msg
#def decrypt_message(encoded_encrypted_msg, privatekey):
#	decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
#	decoded_decrypted_msg = privatekey.decrypt(decoded_encrypted_msg)
#	return decoded_decrypted_msg

#a_message = "This is the illustration of RSA algorithm of asymmetric cryptography"
#privatekey , publickey = generate_keys()
#a_message = sys.argv[1]
#privatekey = RSA.importKey(open("private.pem", "rb"))
#publickey = RSA.importKey(open("public.pem","rb"))

#encrypted_msg = encrypt_message(a_message , publickey)
#decrypted_msg = decrypt_message(encrypted_msg, privatekey)
#pm = privatekey.exportKey(format='PEM')
#pum = publickey.exportKey(format='PEM')

#print " Original content: %s - (%d)" % (a_message, len(a_message))
#print(encrypted_msg)
#print "Decrypted message: %s - (%d)" % (decrypted_msg, len(decrypted_msg))
