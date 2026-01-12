--!native
--!strict
--!optimize 2

local BitOps = require(script.Parent.Parent.Modules.BitOps)
local Entropy = require(script.Parent.Parent.Modules.Entropy)
local SHA256 = require(script.Parent.Parent.Modules.SHA256)
local SHA512 = require(script.Parent.Parent.Modules.SHA512)
local Whirlpool = require(script.Parent.Parent.Modules.Whirlpool)
local HMAC = require(script.Parent.Parent.Modules.HMAC)
local PBKDF2 = require(script.Parent.Parent.Modules.PBKDF2)
local AES = require(script.Parent.Parent.Modules.AES)
local Serpent = require(script.Parent.Parent.Modules.Serpent)
local Twofish = require(script.Parent.Parent.Modules.Twofish)
local XTS = require(script.Parent.Parent.Modules.XTS)
local CipherCascade = require(script.Parent.Parent.Modules.CipherCascade)

local table_create = table.create
local string_byte = string.byte
local bxor = bit32.bxor

export type ByteArray = { number }
export type HashAlgorithm = "SHA256" | "SHA512" | "Whirlpool"
export type CipherType = "AES" | "Serpent" | "Twofish"
export type CascadeType = "AES" | "Serpent" | "Twofish" | "AES-Twofish" | "AES-Twofish-Serpent" | "Serpent-AES" | "Serpent-Twofish-AES" | "Twofish-Serpent"

export type VolumeHeader = {
	salt: ByteArray,
	encryptedHeader: ByteArray,
}

export type DecryptedHeader = {
	magic: string,
	version: number,
	minVersion: number,
	crc32Header: number,
	volumeCreationTime: number,
	headerCreationTime: number,
	hiddenVolumeSize: number,
	volumeSize: number,
	encryptedAreaStart: number,
	encryptedAreaSize: number,
	flags: number,
	sectorSize: number,
	crc32Keys: number,
	masterKey: ByteArray,
	secondaryKey: ByteArray,
}

export type VolumeConfig = {
	cipher: CascadeType,
	hash: HashAlgorithm,
	iterations: number?,
	volumeSize: number,
	sectorSize: number?,
	hiddenVolume: boolean?,
}

export type Volume = {
	config: VolumeConfig,
	header: VolumeHeader,
	cascadeKey: any,
	isOpen: boolean,
}

local HEADER_SIZE: number = 512
local SALT_SIZE: number = 64
local MASTER_KEY_SIZE: number = 64
local SECONDARY_KEY_SIZE: number = 64
local SECTOR_SIZE: number = 512
local MAGIC: string = "VERA"
local VERSION: number = 5
local MIN_VERSION: number = 5

local DEFAULT_ITERATIONS: { [HashAlgorithm]: number } = {
	SHA256 = 500000,
	SHA512 = 500000,
	Whirlpool = 500000,
}

local CRC32_TABLE: { number } = table_create(256) :: { number }
do
	for i = 0, 255 do
		local crc = i
		for _ = 1, 8 do
			if bit32.band(crc, 1) ~= 0 then crc = bxor(bit32.rshift(crc, 1), 0xEDB88320)
			else crc = bit32.rshift(crc, 1) end
		end
		CRC32_TABLE[i] = crc
	end
end

local function crc32(data: ByteArray, offset: number?, length: number?): number
	local start = offset or 1
	local len = length or #data
	local crc = 0xFFFFFFFF

	for i = start, start + len - 1 do
		local idx = bit32.band(bxor(crc, data[i]), 0xFF)
		crc = bxor(bit32.rshift(crc, 8), CRC32_TABLE[idx])
	end

	return bxor(crc, 0xFFFFFFFF)
end

local function generate_salt(): ByteArray
	return Entropy.random_bytes(SALT_SIZE)
end

local function generate_master_keys(): (ByteArray, ByteArray)
	return Entropy.random_bytes(MASTER_KEY_SIZE), Entropy.random_bytes(SECONDARY_KEY_SIZE)
end

local function derive_keys(password: string, salt: ByteArray, hash: HashAlgorithm, iterations: number?, keyLength: number?): ByteArray
	local passwordBytes = table_create(#password) :: ByteArray
	for i = 1, #password do passwordBytes[i] = string_byte(password, i) end

	local iters = iterations or DEFAULT_ITERATIONS[hash]
	local kLen = keyLength or 128  -- 128 bytes for header key + secondary header key

	return PBKDF2.derive(hash, passwordBytes, salt, iters, kLen)
end

local function serialize_header(header: DecryptedHeader): ByteArray
	local bytes = table_create(448) :: ByteArray  -- Header size minus salt (512 - 64)

	-- Initialize with zeros
	for i = 1, 448 do bytes[i] = 0 end

	-- Magic (4 bytes)
	for i = 1, 4 do bytes[i] = string_byte(header.magic, i) end

	-- Version (2 bytes, little endian)
	bytes[5] = bit32.band(header.version, 0xFF)
	bytes[6] = bit32.band(bit32.rshift(header.version, 8), 0xFF)

	-- Min version (2 bytes, little endian)
	bytes[7] = bit32.band(header.minVersion, 0xFF)
	bytes[8] = bit32.band(bit32.rshift(header.minVersion, 8), 0xFF)

	-- CRC32 of header (4 bytes, little endian) - placeholder, calculated later
	-- bytes[9-12] = CRC32

	-- Reserved (16 bytes)
	-- bytes[13-28] = 0

	-- Hidden volume size (8 bytes, little endian)
	local hvs = header.hiddenVolumeSize
	for i = 0, 7 do bytes[29 + i] = bit32.band(bit32.rshift(hvs, i * 8), 0xFF) end

	-- Volume size (8 bytes, little endian)
	local vs = header.volumeSize
	for i = 0, 7 do bytes[37 + i] = bit32.band(bit32.rshift(vs, i * 8), 0xFF) end

	-- Encrypted area start (8 bytes, little endian)
	local eas = header.encryptedAreaStart
	for i = 0, 7 do bytes[45 + i] = bit32.band(bit32.rshift(eas, i * 8), 0xFF) end

	-- Encrypted area size (8 bytes, little endian)
	local easz = header.encryptedAreaSize
	for i = 0, 7 do bytes[53 + i] = bit32.band(bit32.rshift(easz, i * 8), 0xFF) end

	-- Flags (4 bytes, little endian)
	bytes[61] = bit32.band(header.flags, 0xFF)
	bytes[62] = bit32.band(bit32.rshift(header.flags, 8), 0xFF)
	bytes[63] = bit32.band(bit32.rshift(header.flags, 16), 0xFF)
	bytes[64] = bit32.band(bit32.rshift(header.flags, 24), 0xFF)

	-- Sector size (4 bytes, little endian)
	bytes[65] = bit32.band(header.sectorSize, 0xFF)
	bytes[66] = bit32.band(bit32.rshift(header.sectorSize, 8), 0xFF)
	bytes[67] = bit32.band(bit32.rshift(header.sectorSize, 16), 0xFF)
	bytes[68] = bit32.band(bit32.rshift(header.sectorSize, 24), 0xFF)

	-- Reserved (120 bytes)
	-- bytes[69-188] = 0

	-- CRC32 of keys (4 bytes, little endian)
	-- bytes[189-192] = CRC32 of master keys

	-- Master key (64 bytes)
	for i = 1, 64 do bytes[192 + i] = header.masterKey[i] end

	-- Secondary key (64 bytes)
	for i = 1, 64 do bytes[256 + i] = header.secondaryKey[i] end

	-- Calculate CRC32 of keys
	local keysCrc = crc32(bytes, 193, 128)
	bytes[189] = bit32.band(keysCrc, 0xFF)
	bytes[190] = bit32.band(bit32.rshift(keysCrc, 8), 0xFF)
	bytes[191] = bit32.band(bit32.rshift(keysCrc, 16), 0xFF)
	bytes[192] = bit32.band(bit32.rshift(keysCrc, 24), 0xFF)

	-- Calculate CRC32 of header (bytes 5-188)
	local headerCrc = crc32(bytes, 5, 184)
	bytes[9] = bit32.band(headerCrc, 0xFF)
	bytes[10] = bit32.band(bit32.rshift(headerCrc, 8), 0xFF)
	bytes[11] = bit32.band(bit32.rshift(headerCrc, 16), 0xFF)
	bytes[12] = bit32.band(bit32.rshift(headerCrc, 24), 0xFF)

	return bytes
end

local function deserialize_header(bytes: ByteArray): DecryptedHeader?
	-- Check magic
	local magic = string.char(bytes[1], bytes[2], bytes[3], bytes[4])
	if magic ~= MAGIC then return nil end

	-- Version
	local version = bytes[5] + bytes[6] * 256
	local minVersion = bytes[7] + bytes[8] * 256

	-- CRC32 of header
	local crc32Header = bytes[9] + bytes[10] * 256 + bytes[11] * 65536 + bytes[12] * 16777216

	-- Verify header CRC
	local calculatedCrc = crc32(bytes, 5, 184)
	if calculatedCrc ~= crc32Header then return nil end

	-- Hidden volume size
	local hiddenVolumeSize = 0
	for i = 0, 7 do hiddenVolumeSize = hiddenVolumeSize + bytes[29 + i] * (256 ^ i) end

	-- Volume size
	local volumeSize = 0
	for i = 0, 7 do volumeSize = volumeSize + bytes[37 + i] * (256 ^ i) end

	-- Encrypted area start
	local encryptedAreaStart = 0
	for i = 0, 7 do encryptedAreaStart = encryptedAreaStart + bytes[45 + i] * (256 ^ i) end

	-- Encrypted area size
	local encryptedAreaSize = 0
	for i = 0, 7 do encryptedAreaSize = encryptedAreaSize + bytes[53 + i] * (256 ^ i) end

	-- Flags
	local flags = bytes[61] + bytes[62] * 256 + bytes[63] * 65536 + bytes[64] * 16777216

	-- Sector size
	local sectorSize = bytes[65] + bytes[66] * 256 + bytes[67] * 65536 + bytes[68] * 16777216

	-- CRC32 of keys
	local crc32Keys = bytes[189] + bytes[190] * 256 + bytes[191] * 65536 + bytes[192] * 16777216

	-- Verify keys CRC
	local calculatedKeysCrc = crc32(bytes, 193, 128)
	if calculatedKeysCrc ~= crc32Keys then return nil end

	-- Master key
	local masterKey = table_create(64) :: ByteArray
	for i = 1, 64 do masterKey[i] = bytes[192 + i] end

	-- Secondary key
	local secondaryKey = table_create(64) :: ByteArray
	for i = 1, 64 do secondaryKey[i] = bytes[256 + i] end

	return {
		magic = magic,
		version = version,
		minVersion = minVersion,
		crc32Header = crc32Header,
		volumeCreationTime = 0,
		headerCreationTime = 0,
		hiddenVolumeSize = hiddenVolumeSize,
		volumeSize = volumeSize,
		encryptedAreaStart = encryptedAreaStart,
		encryptedAreaSize = encryptedAreaSize,
		flags = flags,
		sectorSize = sectorSize,
		crc32Keys = crc32Keys,
		masterKey = masterKey,
		secondaryKey = secondaryKey,
	}
end

local function encrypt_header(headerBytes: ByteArray, headerKey: ByteArray, cipher: CascadeType): ByteArray
	-- Create XTS key for header encryption
	local cascadeKey = CipherCascade.create_key(cipher, headerKey)

	-- Encrypt header as sector 0
	return CipherCascade.encrypt_sector(cascadeKey, 0, headerBytes)
end

local function decrypt_header(encryptedHeader: ByteArray, headerKey: ByteArray, cipher: CascadeType): ByteArray
	-- Create XTS key for header decryption
	local cascadeKey = CipherCascade.create_key(cipher, headerKey)

	-- Decrypt header as sector 0
	return CipherCascade.decrypt_sector(cascadeKey, 0, encryptedHeader)
end

local function create_volume(password: string, config: VolumeConfig): Volume
	local hash = config.hash
	local cipher = config.cipher
	local iterations = config.iterations or DEFAULT_ITERATIONS[hash]
	local sectorSize = config.sectorSize or SECTOR_SIZE

	-- Generate salt
	local salt = generate_salt()

	-- Generate master key(s)
	local masterKey, secondaryKey = generate_master_keys()

	local keyLength = CipherCascade.get_key_length(cipher)
	local derivedKey = derive_keys(password, salt, hash, iterations, keyLength)

	local header: DecryptedHeader = {
		magic = MAGIC,
		version = VERSION,
		minVersion = MIN_VERSION,
		crc32Header = 0,
		volumeCreationTime = os.time(),
		headerCreationTime = os.time(),
		hiddenVolumeSize = 0,
		volumeSize = config.volumeSize,
		encryptedAreaStart = HEADER_SIZE,
		encryptedAreaSize = config.volumeSize,
		flags = 0,
		sectorSize = sectorSize,
		crc32Keys = 0,
		masterKey = masterKey,
		secondaryKey = secondaryKey,
	}

	local headerBytes = serialize_header(header)

	local paddedHeader = table_create(SECTOR_SIZE) :: ByteArray
	for i = 1, #headerBytes do paddedHeader[i] = headerBytes[i] end
	for i = #headerBytes + 1, SECTOR_SIZE do paddedHeader[i] = Entropy.random_bytes(1)[1] end

	local encryptedHeader = encrypt_header(paddedHeader, derivedKey, cipher)

	local volumeKeyMaterial = table_create(128) :: ByteArray
	for i = 1, 64 do volumeKeyMaterial[i] = masterKey[i] end
	for i = 1, 64 do volumeKeyMaterial[64 + i] = secondaryKey[i] end

	local cascadeKey = CipherCascade.create_key(cipher, volumeKeyMaterial)

	return {
		config = config,
		header = {
			salt = salt,
			encryptedHeader = encryptedHeader,
		},
		cascadeKey = cascadeKey,
		isOpen = true,
	}
end

local function open_volume(password: string, volumeHeader: VolumeHeader, cipher: CascadeType, hash: HashAlgorithm, iterations: number?): Volume?
	local iters = iterations or DEFAULT_ITERATIONS[hash]

	local keyLength = CipherCascade.get_key_length(cipher)
	local derivedKey = derive_keys(password, volumeHeader.salt, hash, iters, keyLength)

	local decryptedHeaderBytes = decrypt_header(volumeHeader.encryptedHeader, derivedKey, cipher)

	local header = deserialize_header(decryptedHeaderBytes)
	if not header then return nil end

	local volumeKeyMaterial = table_create(128) :: ByteArray
	for i = 1, 64 do volumeKeyMaterial[i] = header.masterKey[i] end
	for i = 1, 64 do volumeKeyMaterial[64 + i] = header.secondaryKey[i] end

	local cascadeKey = CipherCascade.create_key(cipher, volumeKeyMaterial)

	return {
		config = {
			cipher = cipher,
			hash = hash,
			iterations = iters,
			volumeSize = header.volumeSize,
			sectorSize = header.sectorSize,
		},
		header = volumeHeader,
		cascadeKey = cascadeKey,
		isOpen = true,
	}
end

local function try_open_volume(password: string, volumeHeader: VolumeHeader): Volume?
	local ciphers: { CascadeType } = { "AES", "Serpent", "Twofish", "AES-Twofish", "AES-Twofish-Serpent", "Serpent-AES", "Serpent-Twofish-AES", "Twofish-Serpent" }
	local hashes: { HashAlgorithm } = { "SHA512", "SHA256", "Whirlpool" }

	for _, cipher in ipairs(ciphers) do
		for _, hash in ipairs(hashes) do
			local volume = open_volume(password, volumeHeader, cipher, hash)
			if volume then return volume end
		end
	end

	return nil
end

-- We can just wipe keys here
local function close_volume(volume: Volume): ()
	if volume.cascadeKey then
		volume.cascadeKey = nil
	end
	volume.isOpen = false
end

-- Encrypt data within volume
local function encrypt_data(volume: Volume, sectorNum: number, plaintext: ByteArray): ByteArray
	if not volume.isOpen then error("volume is not open") end
	return CipherCascade.encrypt(volume.cascadeKey, sectorNum, plaintext)
end

-- Decrypt data within volume
local function decrypt_data(volume: Volume, sectorNum: number, ciphertext: ByteArray): ByteArray
	if not volume.isOpen then error("volume is not open") end
	return CipherCascade.decrypt(volume.cascadeKey, sectorNum, ciphertext)
end

local function encrypt_sector(volume: Volume, sectorNum: number, plaintext: ByteArray): ByteArray
	if not volume.isOpen then error("volume is not open") end
	return CipherCascade.encrypt_sector(volume.cascadeKey, sectorNum, plaintext)
end

local function decrypt_sector(volume: Volume, sectorNum: number, ciphertext: ByteArray): ByteArray
	if not volume.isOpen then error("volume is not open") end
	return CipherCascade.decrypt_sector(volume.cascadeKey, sectorNum, ciphertext)
end

local function get_header_bytes(volume: Volume): ByteArray
	local headerBytes = table_create(SALT_SIZE + SECTOR_SIZE) :: ByteArray

	-- Salt
	for i = 1, SALT_SIZE do headerBytes[i] = volume.header.salt[i] end

	-- Encrypted header
	for i = 1, SECTOR_SIZE do headerBytes[SALT_SIZE + i] = volume.header.encryptedHeader[i] end

	return headerBytes
end

-- Parse volume header from bytes
local function parse_header_bytes(bytes: ByteArray): VolumeHeader
	local salt = table_create(SALT_SIZE) :: ByteArray
	local encryptedHeader = table_create(SECTOR_SIZE) :: ByteArray

	for i = 1, SALT_SIZE do salt[i] = bytes[i] end
	for i = 1, SECTOR_SIZE do encryptedHeader[i] = bytes[SALT_SIZE + i] end

	return { salt = salt, encryptedHeader = encryptedHeader }
end

local function change_password(volume: Volume, oldPassword: string, newPassword: string, newHash: HashAlgorithm?, newIterations: number?): boolean
	if not volume.isOpen then return false end

	local hash = newHash or volume.config.hash
	local iterations = newIterations or volume.config.iterations or DEFAULT_ITERATIONS[hash]
	local cipher = volume.config.cipher

	-- Generate new salt
	local newSalt = generate_salt()

	-- Derive new header key
	local keyLength = CipherCascade.get_key_length(cipher)
	local newDerivedKey = derive_keys(newPassword, newSalt, hash, iterations, keyLength)

	-- Get current master keys by decrypting old header
	local oldDerivedKey = derive_keys(oldPassword, volume.header.salt, volume.config.hash, volume.config.iterations or DEFAULT_ITERATIONS[volume.config.hash], keyLength)
	local decryptedHeaderBytes = decrypt_header(volume.header.encryptedHeader, oldDerivedKey, cipher)
	local header = deserialize_header(decryptedHeaderBytes)

	if not header then return false end

	local headerBytes = serialize_header(header)
	local paddedHeader = table_create(SECTOR_SIZE) :: ByteArray
	for i = 1, #headerBytes do paddedHeader[i] = headerBytes[i] end
	for i = #headerBytes + 1, SECTOR_SIZE do paddedHeader[i] = Entropy.random_bytes(1)[1] end

	local newEncryptedHeader = encrypt_header(paddedHeader, newDerivedKey, cipher)

	volume.header.salt = newSalt
	volume.header.encryptedHeader = newEncryptedHeader
	volume.config.hash = hash
	volume.config.iterations = iterations

	return true
end

local function pkcs7_pad(data: ByteArray, blockSize: number): ByteArray
	local paddingLength = blockSize - (#data % blockSize)
	if paddingLength == 0 then paddingLength = blockSize end

	local padded = table.clone(data)
	for i = 1, paddingLength do
		table.insert(padded, paddingLength)
	end
	return padded
end

local function pkcs7_unpad(data: ByteArray): ByteArray?
	local dataLen = #data
	if dataLen == 0 then return nil end

	local paddingLength = data[dataLen]
	if paddingLength == 0 or paddingLength > 16 or paddingLength > dataLen then return nil end

	-- Here, we have to verify that all padding bytes match the padding length value
	for i = dataLen - paddingLength + 1, dataLen do
		if data[i] ~= paddingLength then return nil end
	end

	local unpaddedLen = dataLen - paddingLength
	local unpadded = table_create(unpaddedLen) :: ByteArray
	for i = 1, unpaddedLen do unpadded[i] = data[i] end
	return unpadded
end

local function simple_encrypt(password: string, plaintext: ByteArray, cipher: CascadeType?, hash: HashAlgorithm?, iterations: number?): { salt: ByteArray, ciphertext: ByteArray }
	local c = cipher or "AES-Twofish-Serpent"
	local h = hash or "SHA512"
	local iters = iterations or DEFAULT_ITERATIONS[h]

	-- We do this because, i.e., the AES-Twofish-Serpent cascade needs 16 byte aligned blocks
	local padded = pkcs7_pad(plaintext, 16)

	local salt = generate_salt()
	local keyLength = CipherCascade.get_key_length(c)
	local key = derive_keys(password, salt, h, iters, keyLength)

	local cascadeKey = CipherCascade.create_key(c, key)
	local ciphertext = CipherCascade.encrypt(cascadeKey, 0, padded)

	return { salt = salt, ciphertext = ciphertext }
end

local function simple_decrypt(password: string, salt: ByteArray, ciphertext: ByteArray, cipher: CascadeType?, hash: HashAlgorithm?, iterations: number?): ByteArray?
	local c = cipher or "AES-Twofish-Serpent"
	local h = hash or "SHA512"
	local iters = iterations or DEFAULT_ITERATIONS[h]

	local keyLength = CipherCascade.get_key_length(c)
	local key = derive_keys(password, salt, h, iters, keyLength)

	local cascadeKey = CipherCascade.create_key(c, key)
	local decrypted = CipherCascade.decrypt(cascadeKey, 0, ciphertext)

	-- Auto-unpad the padded data (returns nil on invalid padding)
	return pkcs7_unpad(decrypted)
end

return {
	HEADER_SIZE = HEADER_SIZE,
	SALT_SIZE = SALT_SIZE,
	SECTOR_SIZE = SECTOR_SIZE,
	MASTER_KEY_SIZE = MASTER_KEY_SIZE,
	VERSION = VERSION,

	create_volume = create_volume,
	open_volume = open_volume,
	try_open_volume = try_open_volume,
	close_volume = close_volume,
	change_password = change_password,

	encrypt_data = encrypt_data,
	decrypt_data = decrypt_data,
	encrypt_sector = encrypt_sector,
	decrypt_sector = decrypt_sector,

	get_header_bytes = get_header_bytes,
	parse_header_bytes = parse_header_bytes,

	simple_encrypt = simple_encrypt,
	simple_decrypt = simple_decrypt,

	derive_keys = derive_keys,
	generate_salt = generate_salt,
	generate_master_keys = generate_master_keys,

	crc32 = crc32,
	DEFAULT_ITERATIONS = DEFAULT_ITERATIONS,

	BitOps = BitOps,
	Entropy = Entropy,
	SHA256 = SHA256,
	SHA512 = SHA512,
	Whirlpool = Whirlpool,
	HMAC = HMAC,
	PBKDF2 = PBKDF2,
	AES = AES,
	Serpent = Serpent,
	Twofish = Twofish,
	XTS = XTS,
	CipherCascade = CipherCascade,
}