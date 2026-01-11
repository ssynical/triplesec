### Random Generation

#### `random_bytes(length: number)`
**Returns:** `ByteArray`  
Generates cryptographically secure bytes.

#### `random_int(min: number, max: number)`
**Returns:** `number`  
Generates secure random integer.

#### `random_hex(length: number)`
**Returns:** `string`  
Generates random hex string.

### Seeding

#### `seed(seedBytes: ByteArray)`
**Returns:** `void`  
Seeds random generator.

#### `seed_from_string(seedString: string)`
**Returns:** `void`  
Seeds from string.

### Utilities

#### `shuffle(array: { any })`
**Returns:** `{ any }`  
Cryptographically shuffles array.

#### `sample(array: { any }, count: number)`
**Returns:** `{ any }`  
Securely samples elements.