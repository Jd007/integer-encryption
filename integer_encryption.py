import hashlib, base64

# This key should be a str, used in encoding and decoding of the int. Must be kept secret for the
# encoding to be secure. 32-char or more randomly generated str recommended.
INTEGER_ENCODE_PRIVATE_KEY = ''

def safe_encode_int(i):
	'''
	Given a 32-bit signed integer (between 1 and 2^31-2), returns a URL-safe Base64 encoded string
	using a private str INTEGER_ENCODE_PRIVATE_KEY as key. The returned string can be made public
	and the original integer can only be decoded with the same private key and the safe_decode_int
	function.

	Returns the (non-empty, URL-safe) encoded string on success, empty string on failure.
	'''
	if not isinstance(i, (int, long, float)):
		return ''
	i = int(i)
	if i < 0 or i > 2147483647:
		return ''

	part1_hex = hashlib.sha1(str(i) + INTEGER_ENCODE_PRIVATE_KEY).hexdigest()[:16]
	part2_init_hex = hashlib.sha1(part1_hex + INTEGER_ENCODE_PRIVATE_KEY).hexdigest()[:8]
	part2_init_dec = int(part2_init_hex, 16)
	part2_dec = (part2_init_dec - i) if (i < part2_init_dec) else (part2_init_dec + i)
	part2_hex = str(hex(part2_dec).split('x')[1])
	if len(part2_hex) < 8:
		part2_hex = ('0' * (8 - len(part2_hex))) + part2_hex
	part3_hex = hashlib.sha1(part1_hex + part2_hex + INTEGER_ENCODE_PRIVATE_KEY).hexdigest()[:8]

	final_hex = part1_hex + part2_hex + part3_hex
	final_bin = final_hex.decode('hex')
	final_b64 = base64.urlsafe_b64encode(final_bin).strip('=') # Remove the padding to shorten the result

	return final_b64

def safe_decode_int(s):
	'''
	Functional reverse of safe_encode_int, given the encoded string, returns the original integer. The private
	key (INTEGER_ENCODE_PRIVATE_KEY) must be the same as the one used during encoding for the correct decoded
	value.

	Returns the decoded integer on success, -1 on failure.
	'''
	if not isinstance(s, (str)):
		return -1
	s = s.strip()

	# Add the Base64 padding if removed during encoding
	if len(s) == 22:
		s += '=='
	else:
		if len(s) % 4 != 0 and not s.endswith('='):
			if len(s) % 3 == 0:
				s += '='
			elif len(s) % 2 == 0:
				s += '=='
			else:
				return -1
	hex_s = base64.urlsafe_b64decode(s).encode('hex')
	if len(hex_s) != 32:
		return -1

	part1_hex = hex_s[:16]
	part2_hex = hex_s[16:24]
	part3_hex = hex_s[24:]
	expanded_2 = hashlib.sha1(part1_hex + INTEGER_ENCODE_PRIVATE_KEY).hexdigest()[:8]
	expanded_3 = hashlib.sha1(part1_hex + part2_hex + INTEGER_ENCODE_PRIVATE_KEY).hexdigest()[:8]
	if expanded_3 != part3_hex: # part3_hex and expanded_3 act as a checksum, and must be equal
		return -1

	return abs(int(part2_hex, 16) - int(expanded_2, 16))

if __name__ == '__main__':
	test_int = 38367395
	print 'Testing with int:', test_int

	encoded_str = safe_encode_int(test_int)
	print 'Encoded str:', encoded_str

	decoded_int = safe_decode_int(encoded_str)

	assert(test_int == decoded_int)
	print 'Decoded int:', decoded_int