--!native
--!strict
--!optimize 2

local AES = require(script.Parent.AES)
local Serpent = require(script.Parent.Serpent)
local Twofish = require(script.Parent.Twofish)
local XTS = require(script.Parent.XTS)

local table_create = table.create
local bxor = bit32.bxor

export type ByteArray = { number }
export type CipherType = "AES" | "Serpent" | "Twofish"

export type CascadeType = 
		"AES" | "Serpent" | "Twofish" |
	"AES-Twofish" | "AES-Twofish-Serpent" |
	"Serpent-AES" | "Serpent-Twofish-AES" |
	"Twofish-Serpent"

export type CascadeKey = {
	cascadeType: CascadeType,
	xtsKeys: { any },
	cipherOrder: { CipherType },
}

local BLOCK_SIZE: number = 16
local SECTOR_SIZE: number = 512
local KEY_SIZE: number = 32

local CASCADE_CONFIG: { [CascadeType]: { CipherType } } = {
	["AES"] = { "AES" },
	["Serpent"] = { "Serpent" },
	["Twofish"] = { "Twofish" },
	["AES-Twofish"] = { "AES", "Twofish" },
	["AES-Twofish-Serpent"] = { "AES", "Twofish", "Serpent" },
	["Serpent-AES"] = { "Serpent", "AES" },
	["Serpent-Twofish-AES"] = { "Serpent", "Twofish", "AES" },
	["Twofish-Serpent"] = { "Twofish", "Serpent" },
}

local function get_key_length(cascadeType: CascadeType): number
	local config = CASCADE_CONFIG[cascadeType]
	return #config * KEY_SIZE * 2  -- Each cipher needs 2 keys for XTS (64 bytes per cipher)
end

-- Create cascade key from combined key material
local function create_key(cascadeType: CascadeType, keyMaterial: ByteArray): CascadeKey
	local config = CASCADE_CONFIG[cascadeType]
	local numCiphers = #config
	local requiredLen = numCiphers * 64  -- 64 bytes per cipher (2x 32-byte keys for XTS)

	if #keyMaterial < requiredLen then error("Insufficient key material for cascade") end

	local xtsKeys: { any } = table_create(numCiphers)

	for i = 1, numCiphers do
		local offset = (i - 1) * 64 + 1
		local combinedKey = table_create(64) :: ByteArray
		for j = 1, 64 do combinedKey[j] = keyMaterial[offset + j - 1] end
		xtsKeys[i] = XTS.create_key_combined(config[i], combinedKey)
	end

	return {
		cascadeType = cascadeType,
		xtsKeys = xtsKeys,
		cipherOrder = config,
	}
end

local function encrypt_sector(key: CascadeKey, sectorNum: number, plaintext: ByteArray, plaintextOffset: number?): ByteArray
	local pOff = plaintextOffset or 1
	local numCiphers = #key.cipherOrder

	local data = table_create(SECTOR_SIZE) :: ByteArray
	for i = 1, SECTOR_SIZE do data[i] = plaintext[pOff + i - 1] end

	for i = 1, numCiphers do
		data = XTS.encrypt_sector(key.xtsKeys[i], sectorNum, data)
	end

	return data
end

local function decrypt_sector(key: CascadeKey, sectorNum: number, ciphertext: ByteArray, ciphertextOffset: number?): ByteArray
	local cOff = ciphertextOffset or 1
	local numCiphers = #key.cipherOrder

	local data = table_create(SECTOR_SIZE) :: ByteArray
	for i = 1, SECTOR_SIZE do data[i] = ciphertext[cOff + i - 1] end

	for i = numCiphers, 1, -1 do
		data = XTS.decrypt_sector(key.xtsKeys[i], sectorNum, data)
	end

	return data
end

local function encrypt(key: CascadeKey, startSector: number, plaintext: ByteArray): ByteArray
	local dataLen = #plaintext
	local numSectors = math.ceil(dataLen / SECTOR_SIZE)
	local ciphertext = table_create(dataLen) :: ByteArray

	for s = 0, numSectors - 1 do
		local sectorOffset = s * SECTOR_SIZE + 1
		local sectorLen = math.min(SECTOR_SIZE, dataLen - s * SECTOR_SIZE)

		if sectorLen == SECTOR_SIZE then
			local encrypted = encrypt_sector(key, startSector + s, plaintext, sectorOffset)
			for i = 1, SECTOR_SIZE do ciphertext[sectorOffset + i - 1] = encrypted[i] end
		else
			local paddedSector = table_create(SECTOR_SIZE) :: ByteArray
			for i = 1, sectorLen do paddedSector[i] = plaintext[sectorOffset + i - 1] end
			for i = sectorLen + 1, SECTOR_SIZE do paddedSector[i] = 0 end

			local encrypted = encrypt_sector(key, startSector + s, paddedSector)
			for i = 1, sectorLen do ciphertext[sectorOffset + i - 1] = encrypted[i] end
		end
	end

	return ciphertext
end

local function decrypt(key: CascadeKey, startSector: number, ciphertext: ByteArray): ByteArray
	local dataLen = #ciphertext
	local numSectors = math.ceil(dataLen / SECTOR_SIZE)
	local plaintext = table_create(dataLen) :: ByteArray

	for s = 0, numSectors - 1 do
		local sectorOffset = s * SECTOR_SIZE + 1
		local sectorLen = math.min(SECTOR_SIZE, dataLen - s * SECTOR_SIZE)

		if sectorLen == SECTOR_SIZE then
			local decrypted = decrypt_sector(key, startSector + s, ciphertext, sectorOffset)
			for i = 1, SECTOR_SIZE do plaintext[sectorOffset + i - 1] = decrypted[i] end
		else
			local paddedSector = table_create(SECTOR_SIZE) :: ByteArray
			for i = 1, sectorLen do paddedSector[i] = ciphertext[sectorOffset + i - 1] end
			for i = sectorLen + 1, SECTOR_SIZE do paddedSector[i] = 0 end

			local decrypted = decrypt_sector(key, startSector + s, paddedSector)
			for i = 1, sectorLen do plaintext[sectorOffset + i - 1] = decrypted[i] end
		end
	end

	return plaintext
end

local function get_cascade_types(): { CascadeType }
	return {
		"AES", "Serpent", "Twofish",
		"AES-Twofish", "AES-Twofish-Serpent",
		"Serpent-AES", "Serpent-Twofish-AES",
		"Twofish-Serpent",
	}
end

local function get_cipher_order(cascadeType: CascadeType): { CipherType }
	return CASCADE_CONFIG[cascadeType]
end

return {
	BLOCK_SIZE = BLOCK_SIZE,
	SECTOR_SIZE = SECTOR_SIZE,
	KEY_SIZE = KEY_SIZE,

	create_key = create_key,
	get_key_length = get_key_length,

	encrypt_sector = encrypt_sector,
	decrypt_sector = decrypt_sector,

	encrypt = encrypt,
	decrypt = decrypt,

	get_cascade_types = get_cascade_types,
	get_cipher_order = get_cipher_order,
	CASCADE_CONFIG = CASCADE_CONFIG,
}
