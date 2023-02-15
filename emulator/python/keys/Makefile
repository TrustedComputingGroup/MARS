
ak.crt: akpub.pem ak.csr ez.crt
	# Creating the AK Certificate
	openssl x509 -req -in ak.csr -force_pubkey akpub.pem -CA ez.crt -CAkey ez.pem -days 180 -out $@ -set_serial 1

ez.pem:
	# Creating key for EZ
	openssl ecparam -name prime256v1 -genkey -out $@

ez.crt:
	# Creating EZ's self-signed certificate
	openssl req -new -x509 -key ez.pem -out ez.crt -days 730
	# openssl x509 -text -noout -in ez.crt

# assume akpub.pem copied from mars debug output
# akpub.pem: akprv.pem
	# Extracting public key from $@
	# openssl ec -in $< -pubout -out $@

fake.pem:
	# Creating a fake / dummy key
	openssl ecparam -name prime256v1 -genkey -out $@

ak.csr: fake.pem
	# Creating a Cert Signing Request using $< key
	openssl req -new -key $< -days 180 -out $@
	# Create DER from PEM
	# tail -n +2 file.pem | head -n -1 | base64 -d



# Assumes that MARS app used to create uk.csr from Unrestricted Key

uk.crt: uk.csr ez.crt ez.pem
	# Creating the UK Certificate
	openssl x509 -req -in uk.csr -CA ez.crt -CAkey ez.pem -out $@ -set_serial 1

