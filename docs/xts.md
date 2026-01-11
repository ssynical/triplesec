### Key Creation

#### `create_xts_key(cipher: string, key: ByteArray)`
**Returns:** `XTSKey`  
Creates XTS key pair.

### Sector Operations

#### `encrypt_sector(xtsKey: XTSKey, sectorNum: number, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts 512-byte sector.

#### `decrypt_sector(xtsKey: XTSKey, sectorNum: number, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts 512-byte sector.

### Data Operations

#### `encrypt(xtsKey: XTSKey, sectorNum: number, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts arbitrary length data.

#### `decrypt(xtsKey: XTSKey, sectorNum: number, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts arbitrary length data.