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

---

## docs/pbkdf2.md

### Key Derivation

#### `derive(algorithm: HashAlgorithm, password: ByteArray, salt: ByteArray, iterations?: number, keyLength?: number)`
**Returns:** `ByteArray`  
Derives key with PBKDF2.

#### `derive_from_string(algorithm: HashAlgorithm, password: string, salt: ByteArray, iterations?: number, keyLength?: number)`
**Returns:** `ByteArray`  
Derives key from string.

#### `derive_from_strings(algorithm: HashAlgorithm, password: string, salt: string, iterations?: number, keyLength?: number)`
**Returns:** `ByteArray`  
Derives key from strings.

### Algorithm-Specific

#### `derive_sha256(password: ByteArray, salt: ByteArray, iterations?: number, keyLength?: number)`
**Returns:** `ByteArray`  
PBKDF2 with SHA-256.

#### `derive_sha512(password: ByteArray, salt: ByteArray, iterations?: number, keyLength?: number)`
**Returns:** `ByteArray`  
PBKDF2 with SHA-512.

#### `derive_whirlpool(password: ByteArray, salt: ByteArray, iterations?: number, keyLength?: number)`
**Returns:** `ByteArray`  
PBKDF2 with Whirlpool.

### VeraCrypt

#### `derive_veracrypt_keys(algorithm: HashAlgorithm, password: ByteArray, salt: ByteArray, iterations?: number)`
**Returns:** `{ headerKey: ByteArray, secondaryKey: ByteArray }`  
Derives VeraCrypt key pair.

### Utilities

#### `derive_hex(algorithm: HashAlgorithm, password: ByteArray, salt: ByteArray, iterations?: number, keyLength?: number)`
**Returns:** `string`  
Returns hex-encoded key.

#### `get_default_iterations(algorithm: HashAlgorithm)`
**Returns:** `number`  
Returns default iteration count.