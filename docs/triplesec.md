### Simple Encryption

#### `simple_encrypt(password: string, plaintext: ByteArray, cipher?: CascadeType, hash?: HashAlgorithm, iterations?: number)`
**Returns:** `{ salt: ByteArray, ciphertext: ByteArray }`  
Encrypts data with padding.

#### `simple_decrypt(password: string, salt: ByteArray, ciphertext: ByteArray, cipher?: CascadeType, hash?: HashAlgorithm, iterations?: number)`
**Returns:** `ByteArray`  
Decrypts data with unpadding.

### Volume Management

#### `create_volume(password: string, config: VolumeConfig)`
**Returns:** `Volume`  
Creates encrypted volume.

#### `open_volume(password: string, volumeHeader: VolumeHeader, cipher: CascadeType, hash: HashAlgorithm, iterations?: number)`
**Returns:** `Volume?`  
Opens existing volume.

#### `try_open_volume(password: string, volumeHeader: VolumeHeader)`
**Returns:** `Volume?`  
Tries all cipher/hash combinations.

#### `close_volume(volume: Volume)`
**Returns:** `void`  
Wipes keys from memory.

#### `change_password(volume: Volume, oldPassword: string, newPassword: string, newHash?: HashAlgorithm, newIterations?: number)`
**Returns:** `boolean`  
Changes volume password.

### Volume Operations

#### `encrypt_data(volume: Volume, sectorNum: number, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts arbitrary length data.

#### `decrypt_data(volume: Volume, sectorNum: number, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts arbitrary length data.

#### `encrypt_sector(volume: Volume, sectorNum: number, plaintext: ByteArray)`
**Returns:** `ByteArray`  
Encrypts 512-byte sector.

#### `decrypt_sector(volume: Volume, sectorNum: number, ciphertext: ByteArray)`
**Returns:** `ByteArray`  
Decrypts 512-byte sector.

### Volume Header

#### `get_header_bytes(volume: Volume)`
**Returns:** `ByteArray`  
Serializes volume header.

#### `parse_header_bytes(bytes: ByteArray)`
**Returns:** `VolumeHeader`  
Parses volume header.

### Utilities

#### `derive_keys(password: string, salt: ByteArray, hash: HashAlgorithm, iterations?: number, keyLength?: number)`
**Returns:** `ByteArray`  
Derives encryption keys.

#### `generate_salt()`
**Returns:** `ByteArray`  
Generates 64-byte salt.

#### `generate_master_keys()`
**Returns:** `(ByteArray, ByteArray)`  
Generates master key pair.

#### `crc32(data: ByteArray, offset?: number, length?: number)`
**Returns:** `number`  
Calculates CRC32 checksum.