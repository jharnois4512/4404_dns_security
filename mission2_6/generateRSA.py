from Crypto.PublicKey import RSA
def generate_RSA(bits=504):
	new_key = RSA.generate(bits, e=65537)
	#print("new: ", new_key)
	public_key = new_key.publickey().exportKey("PEM")
	#print("pub: ", public_key)
	private_key = new_key.exportKey("PEM")
	#print("priv: ", private_key)
	return private_key, public_key

print("method: ", generate_RSA())

