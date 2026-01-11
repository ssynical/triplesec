### Key Schedule

#### `make_key(key: ByteArray)`
**Returns:** `{ number }`  
Generates round keys.

### Block Operations

#### `encrypt_block(roundKeys: { number }, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts 16-byte block.

#### `decrypt_block(roundKeys: { number }, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts 16-byte block.

### ECB Mode

#### `encrypt_ecb(key: ByteArray, plaintext: ByteArray)`
**Returns:** `ByteArray`  
ECB mode encryption.

#### `decrypt_ecb(key: ByteArray, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
ECB mode decryption.