### Hashing

#### `hash(data: ByteArray)`
**Returns:** `ByteArray`  
Hashes byte array.

#### `hash_string(str: string)`
**Returns:** `ByteArray`  
Hashes string directly.

#### `hash_hex(data: ByteArray)`
**Returns:** `string`  
Returns hex digest.

#### `hash_string_hex(str: string)`
**Returns:** `string`  
Hashes string to hex.

### Stateful Hashing

#### `create_state()`
**Returns:** `HashState`  
Creates hash state.

#### `update(state: HashState, data: ByteArray)`
**Returns:** `void`  
Updates hash incrementally.

#### `finalize(state: HashState)`
**Returns:** `ByteArray`  
Finalizes and returns digest.