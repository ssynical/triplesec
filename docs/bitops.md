### Byte Operations

#### `bytes_to_hex(bytes: ByteArray)`
**Returns:** `string`  
Converts to hex string.

#### `hex_to_bytes(hex: string)`
**Returns:** `ByteArray`  
Converts from hex string.

#### `bytes_to_string(bytes: ByteArray)`
**Returns:** `string`  
Converts to ASCII string.

#### `string_to_bytes(str: string)`
**Returns:** `ByteArray`  
Converts from ASCII string.

### Array Operations

#### `xor_bytes(a: ByteArray, b: ByteArray)`
**Returns:** `ByteArray`  
XORs two byte arrays.

#### `xor_bytes_inplace(a: ByteArray, b: ByteArray)`
**Returns:** `void`  
XORs into first array.

#### `clone_bytes(bytes: ByteArray)`
**Returns:** `ByteArray`  
Deep copies byte array.

#### `compare_bytes(a: ByteArray, b: ByteArray)`
**Returns:** `boolean`  
Constant-time comparison.

### 32-bit Operations

#### `rol32(value: number, shift: number)`
**Returns:** `number`  
Rotates left 32-bit.

#### `ror32(value: number, shift: number)`
**Returns:** `number`  
Rotates right 32-bit.

#### `bytes_to_u32_be(bytes: ByteArray, offset: number)`
**Returns:** `number`  
Reads big-endian uint32.

#### `bytes_to_u32_le(bytes: ByteArray, offset: number)`
**Returns:** `number`  
Reads little-endian uint32.

#### `u32_to_bytes_be(value: number)`
**Returns:** `ByteArray`  
Writes big-endian uint32.

#### `u32_to_bytes_le(value: number)`
**Returns:** `ByteArray`  
Writes little-endian uint32.