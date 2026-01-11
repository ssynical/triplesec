### Key Creation

#### `create_key(cascade: CascadeType, keyMaterial: ByteArray)`
**Returns:** `CascadeKey`  
Creates cascade key.

#### `get_key_length(cascade: CascadeType)`
**Returns:** `number`  
Returns required key length.

### Encryption

#### `encrypt(cascadeKey: CascadeKey, sectorNum: number, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts arbitrary length data.

#### `decrypt(cascadeKey: CascadeKey, sectorNum: number, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts arbitrary length data.

#### `encrypt_sector(cascadeKey: CascadeKey, sectorNum: number, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts 512-byte sector.

#### `decrypt_sector(cascadeKey: CascadeKey, sectorNum: number, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts 512-byte sector.