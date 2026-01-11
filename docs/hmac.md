### HMAC

#### `hmac(algorithm: HashAlgorithm, key: ByteArray, message: ByteArray)`
**Returns:** `ByteArray`  
Computes HMAC digest.

#### `hmac_hex(algorithm: HashAlgorithm, key: ByteArray, message: ByteArray)`
**Returns:** `string`  
Returns hex HMAC.

#### `hmac_string(algorithm: HashAlgorithm, key: string, message: string)`
**Returns:** `ByteArray`  
HMAC from strings.

#### `hmac_string_hex(algorithm: HashAlgorithm, key: string, message: string)`
**Returns:** `string`  
HMAC strings to hex.

### Algorithm-Specific

#### `hmac_sha256(key: ByteArray, message: ByteArray)`
**Returns:** `ByteArray`  
HMAC with SHA-256.

#### `hmac_sha512(key: ByteArray, message: ByteArray)`
**Returns:** `ByteArray`  
HMAC with SHA-512.

#### `hmac_whirlpool(key: ByteArray, message: ByteArray)`
**Returns:** `ByteArray`  
HMAC with Whirlpool.

### Utilities

#### `get_digest_size(algorithm: HashAlgorithm)`
**Returns:** `number`  
Returns hash output size.

#### `get_block_size(algorithm: HashAlgorithm)`
**Returns:** `number`  
Returns hash block size.