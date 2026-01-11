### Key Schedule

#### `expand_key(key: ByteArray)`
**Returns:** `{ number }`  
Expands 256-bit key.

### Block Operations

#### `encrypt_block(expandedKey: { number }, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts 16-byte block.

#### `decrypt_block(expandedKey: { number }, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts 16-byte block.

### ECB Mode

#### `encrypt_ecb(key: ByteArray, plaintext: ByteArray)`
**Returns:** `ByteArray`  
ECB mode encryption.

#### `decrypt_ecb(key: ByteArray, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
ECB mode decryption.