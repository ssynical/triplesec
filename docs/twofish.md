### Key Schedule

#### `make_key(key: ByteArray)`
**Returns:** `TwofishKey`  
Generates Twofish key.

### Block Operations

#### `encrypt_block(twofishKey: TwofishKey, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts 16-byte block.

#### `decrypt_block(twofishKey: TwofishKey, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts 16-byte block.

### ECB Mode

#### `encrypt_ecb(key: ByteArray, plaintext: ByteArray)`
**Returns:** `ByteArray`  
ECB mode encryption.

#### `decrypt_ecb(key: ByteArray, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
ECB mode decryption.