--!native
--!strict
--!optimize 2

--[[
	XEX-based Tweaked-codebook mode with ciphertext Stealing
]]

local AES = require(script.Parent.AES)
local Serpent = require(script.Parent.Serpent)
local Twofish = require(script.Parent.Twofish)

local band, bxor = bit32.band, bit32.bxor
local lshift, rshift = bit32.lshift, bit32.rshift
local table_create = table.create

export type ByteArray = { number }
export type CipherType = "AES" | "Serpent" | "Twofish"

export type CipherModule = {
	BLOCK_SIZE: number,
	KEY_SIZE: number,
	expand_key: (key: ByteArray) -> any,
	encrypt_block: (key: any, input: ByteArray, inputOffset: number?, output: ByteArray?, outputOffset: number?) -> ByteArray,
	decrypt_block: (key: any, input: ByteArray, inputOffset: number?, output: ByteArray?, outputOffset: number?) -> ByteArray,
}

export type XTSKey = {
	cipher: CipherType,
	key1: any,
	key2: any,
}

-- Constants
local BLOCK_SIZE: number = 16
local SECTOR_SIZE: number = 512

local function get_cipher_module(cipher: CipherType): CipherModule
	if cipher == "AES" then return AES
	elseif cipher == "Serpent" then return Serpent
	else return Twofish end
end

-- GF(2^128) multiplication by x (alpha)
-- Polynomial: x^128 + x^7 + x^2 + x + 1
local function gf128_mul_alpha(tweak: ByteArray): ByteArray
	local result = table_create(16) :: ByteArray
	local carry = 0

	for i = 1, 16 do
		local b = tweak[i]
		result[i] = bxor(lshift(b, 1), carry)
		carry = rshift(b, 7)
	end

	-- Reduce if carry out (XOR with 0x87 at byte 0)
	if carry ~= 0 then result[1] = bxor(result[1], 0x87) end

	-- Then, mask to bytes
	for i = 1, 16 do result[i] = band(result[i], 0xFF) end

	return result
end

-- XOR two 16-byte blocks
local function xor_blocks(a: ByteArray, b: ByteArray, offset: number?): ByteArray
	local off = offset or 1
	local result = table_create(16) :: ByteArray
	for i = 1, 16 do result[i] = bxor(a[i], b[off + i - 1]) end
	return result
end

local function xor_blocks_inplace(a: ByteArray, b: ByteArray, aOffset: number?, bOffset: number?): ()
	local aOff = aOffset or 1
	local bOff = bOffset or 1
	for i = 1, 16 do a[aOff + i - 1] = bxor(a[aOff + i - 1], b[bOff + i - 1]) end
end

-- Convert sector number to tweak (little endian 128bit)
local function sector_to_tweak(sectorNum: number): ByteArray
	local tweak = table_create(16) :: ByteArray
	for i = 1, 16 do tweak[i] = 0 end

	-- Store sector number in little endian (lower 64 bits)
	local n = sectorNum
	for i = 1, 8 do
		tweak[i] = band(n, 0xFF)
		n = math.floor(n / 256)
	end

	return tweak
end

-- Create XTS key from two cipher keys
local function create_key(cipher: CipherType, key1: ByteArray, key2: ByteArray): XTSKey
	local cipherModule = get_cipher_module(cipher)
	return {
		cipher = cipher,
		key1 = cipherModule.expand_key(key1),
		key2 = cipherModule.expand_key(key2),
	}
end

-- Create XTS key from combined key (64 bytes = 2x 32-byte keys)
local function create_key_combined(cipher: CipherType, combinedKey: ByteArray): XTSKey
	local key1 = table_create(32) :: ByteArray
	local key2 = table_create(32) :: ByteArray

	for i = 1, 32 do
		key1[i] = combinedKey[i]
		key2[i] = combinedKey[32 + i]
	end

	return create_key(cipher, key1, key2)
end

local function encrypt_sector(key: XTSKey, sectorNum: number, plaintext: ByteArray, plaintextOffset: number?, ciphertext: ByteArray?, ciphertextOffset: number?): ByteArray
	local pOff = plaintextOffset or 1
	local cOff = ciphertextOffset or 1
	local out = ciphertext or table_create(SECTOR_SIZE) :: ByteArray
	local cipherModule = get_cipher_module(key.cipher)

	-- Compute initial tweak: E(K2, sector_number)
	local tweak = sector_to_tweak(sectorNum)
	tweak = cipherModule.encrypt_block(key.key2, tweak)

	-- Process full blocks
	local numBlocks = SECTOR_SIZE // BLOCK_SIZE
	local tempBlock = table_create(16)

	for b = 1, numBlocks do
		local blockOff = pOff + (b - 1) * BLOCK_SIZE
		local outOff = cOff + (b - 1) * BLOCK_SIZE

		-- XOR plaintext with tweak
		for i = 1, 16 do tempBlock[i] = bxor(plaintext[blockOff + i - 1], tweak[i]) end

		-- Encrypt
		local encrypted = cipherModule.encrypt_block(key.key1, tempBlock)

		-- XOR with tweak and store
		for i = 1, 16 do out[outOff + i - 1] = bxor(encrypted[i], tweak[i]) end

		-- Update tweak for next block
		tweak = gf128_mul_alpha(tweak)
	end

	return out
end

local function decrypt_sector(key: XTSKey, sectorNum: number, ciphertext: ByteArray, ciphertextOffset: number?, plaintext: ByteArray?, plaintextOffset: number?): ByteArray
	local cOff = ciphertextOffset or 1
	local pOff = plaintextOffset or 1
	local out = plaintext or table_create(SECTOR_SIZE) :: ByteArray
	local cipherModule = get_cipher_module(key.cipher)

	-- Compute the initial tweak: E(K2, sector_number)
	local tweak = sector_to_tweak(sectorNum)
	tweak = cipherModule.encrypt_block(key.key2, tweak)

	-- Process full blocks
	local numBlocks = SECTOR_SIZE // BLOCK_SIZE
	local tempBlock = table_create(16)

	for b = 1, numBlocks do
		local blockOff = cOff + (b - 1) * BLOCK_SIZE
		local outOff = pOff + (b - 1) * BLOCK_SIZE

		-- XOR ciphertext with tweak
		for i = 1, 16 do tempBlock[i] = bxor(ciphertext[blockOff + i - 1], tweak[i]) end

		-- Decrypt
		local decrypted = cipherModule.decrypt_block(key.key1, tempBlock)

		-- XOR with tweak and store
		for i = 1, 16 do out[outOff + i - 1] = bxor(decrypted[i], tweak[i]) end

		-- Update tweak for next block
		tweak = gf128_mul_alpha(tweak)
	end

	return out
end

-- Encrypt arbitrary length data (spans over multiple sectors)
local function encrypt(key: XTSKey, startSector: number, plaintext: ByteArray): ByteArray
	local dataLen = #plaintext
	local numSectors = math.ceil(dataLen / SECTOR_SIZE)
	local ciphertext = table_create(dataLen) :: ByteArray

	for s = 0, numSectors - 1 do
		local sectorOffset = s * SECTOR_SIZE + 1
		local sectorLen = math.min(SECTOR_SIZE, dataLen - s * SECTOR_SIZE)

		if sectorLen == SECTOR_SIZE then
			-- Full sector
			encrypt_sector(key, startSector + s, plaintext, sectorOffset, ciphertext, sectorOffset)
		else
			local paddedSector = table_create(SECTOR_SIZE) :: ByteArray
			for i = 1, sectorLen do paddedSector[i] = plaintext[sectorOffset + i - 1] end
			for i = sectorLen + 1, SECTOR_SIZE do paddedSector[i] = 0 end

			local encryptedSector = encrypt_sector(key, startSector + s, paddedSector)
			for i = 1, sectorLen do ciphertext[sectorOffset + i - 1] = encryptedSector[i] end
		end
	end

	return ciphertext
end

-- Decrypt arbitrary length data
local function decrypt(key: XTSKey, startSector: number, ciphertext: ByteArray): ByteArray
	local dataLen = #ciphertext
	local numSectors = math.ceil(dataLen / SECTOR_SIZE)
	local plaintext = table_create(dataLen) :: ByteArray

	for s = 0, numSectors - 1 do
		local sectorOffset = s * SECTOR_SIZE + 1
		local sectorLen = math.min(SECTOR_SIZE, dataLen - s * SECTOR_SIZE)

		if sectorLen == SECTOR_SIZE then
			decrypt_sector(key, startSector + s, ciphertext, sectorOffset, plaintext, sectorOffset)
		else
			local paddedSector = table_create(SECTOR_SIZE) :: ByteArray
			for i = 1, sectorLen do paddedSector[i] = ciphertext[sectorOffset + i - 1] end
			for i = sectorLen + 1, SECTOR_SIZE do paddedSector[i] = 0 end

			local decryptedSector = decrypt_sector(key, startSector + s, paddedSector)
			for i = 1, sectorLen do plaintext[sectorOffset + i - 1] = decryptedSector[i] end
		end
	end

	return plaintext
end

local function encrypt_sector_cts(key: XTSKey, sectorNum: number, plaintext: ByteArray, dataLen: number): ByteArray
	if dataLen < BLOCK_SIZE then error("data must be at least one block") end
	if dataLen % BLOCK_SIZE == 0 then return encrypt_sector(key, sectorNum, plaintext) end

	local cipherModule = get_cipher_module(key.cipher)
	local ciphertext = table_create(dataLen) :: ByteArray

	-- Compute the initial tweak
	local tweak = sector_to_tweak(sectorNum)
	tweak = cipherModule.encrypt_block(key.key2, tweak)

	-- Then, process all the full blocks except the last two
	local numFullBlocks = dataLen // BLOCK_SIZE
	local remainder = dataLen % BLOCK_SIZE
	local tempBlock = table_create(16) :: ByteArray

	for b = 1, numFullBlocks - 1 do
		local blockOff = (b - 1) * BLOCK_SIZE + 1

		for i = 1, 16 do tempBlock[i] = bxor(plaintext[blockOff + i - 1], tweak[i]) end
		local encrypted = cipherModule.encrypt_block(key.key1, tempBlock)
		for i = 1, 16 do ciphertext[blockOff + i - 1] = bxor(encrypted[i], tweak[i]) end

		tweak = gf128_mul_alpha(tweak)
	end

	-- Handle the last two blocks with ciphertext stealing
	local lastFullBlockOff = (numFullBlocks - 1) * BLOCK_SIZE + 1
	local partialBlockOff = numFullBlocks * BLOCK_SIZE + 1

	-- Encrypt the second-to-last block
	for i = 1, 16 do tempBlock[i] = bxor(plaintext[lastFullBlockOff + i - 1], tweak[i]) end
	local cc = cipherModule.encrypt_block(key.key1, tempBlock)
	for i = 1, 16 do cc[i] = bxor(cc[i], tweak[i]) end

	local nextTweak = gf128_mul_alpha(tweak)

	-- Create padded last block
	local pp = table_create(16)
	for i = 1, remainder do pp[i] = plaintext[partialBlockOff + i - 1] end
	for i = remainder + 1, 16 do pp[i] = cc[i] end

	-- Encrypt the padded block
	for i = 1, 16 do tempBlock[i] = bxor(pp[i], nextTweak[i]) end
	local cp = cipherModule.encrypt_block(key.key1, tempBlock)
	for i = 1, 16 do cp[i] = bxor(cp[i], nextTweak[i]) end

	-- Output: swap order of last two ciphertext blocks
	for i = 1, 16 do ciphertext[lastFullBlockOff + i - 1] = cp[i] end
	for i = 1, remainder do ciphertext[partialBlockOff + i - 1] = cc[i] end

	return ciphertext
end

local function decrypt_sector_cts(key: XTSKey, sectorNum: number, ciphertext: ByteArray, dataLen: number): ByteArray
	if dataLen < BLOCK_SIZE then error("Data must be at least one block") end
	if dataLen % BLOCK_SIZE == 0 then return decrypt_sector(key, sectorNum, ciphertext) end

	local cipherModule = get_cipher_module(key.cipher)
	local plaintext = table_create(dataLen) :: ByteArray

	local tweak = sector_to_tweak(sectorNum)
	tweak = cipherModule.encrypt_block(key.key2, tweak)

	local numFullBlocks = dataLen // BLOCK_SIZE
	local remainder = dataLen % BLOCK_SIZE
	local tempBlock = table_create(16) :: ByteArray

	for b = 1, numFullBlocks - 1 do
		local blockOff = (b - 1) * BLOCK_SIZE + 1

		for i = 1, 16 do tempBlock[i] = bxor(ciphertext[blockOff + i - 1], tweak[i]) end
		local decrypted = cipherModule.decrypt_block(key.key1, tempBlock)
		for i = 1, 16 do plaintext[blockOff + i - 1] = bxor(decrypted[i], tweak[i]) end

		tweak = gf128_mul_alpha(tweak)
	end

	local lastFullBlockOff = (numFullBlocks - 1) * BLOCK_SIZE + 1
	local partialBlockOff = numFullBlocks * BLOCK_SIZE + 1
	local nextTweak = gf128_mul_alpha(tweak)

	-- Decrypt the encrypted padded block
	for i = 1, 16 do tempBlock[i] = bxor(ciphertext[lastFullBlockOff + i - 1], nextTweak[i]) end
	local pp = cipherModule.decrypt_block(key.key1, tempBlock)
	for i = 1, 16 do pp[i] = bxor(pp[i], nextTweak[i]) end

	-- Reconstruct the block
	local cc = table_create(16) :: ByteArray
	for i = 1, remainder do cc[i] = ciphertext[partialBlockOff + i - 1] end
	for i = remainder + 1, 16 do cc[i] = pp[i] end

	-- Decrypt to get the partial plaintext block
	for i = 1, 16 do tempBlock[i] = bxor(cc[i], tweak[i]) end
	local lastPlain = cipherModule.decrypt_block(key.key1, tempBlock)
	for i = 1, 16 do plaintext[lastFullBlockOff + i - 1] = bxor(lastPlain[i], tweak[i]) end

	-- Output partial plaintext
	for i = 1, remainder do plaintext[partialBlockOff + i - 1] = pp[i] end

	return plaintext
end

return {
	BLOCK_SIZE = BLOCK_SIZE,
	SECTOR_SIZE = SECTOR_SIZE,

	create_key = create_key,
	create_key_combined = create_key_combined,

	encrypt_sector = encrypt_sector,
	decrypt_sector = decrypt_sector,
	encrypt_sector_cts = encrypt_sector_cts,
	decrypt_sector_cts = decrypt_sector_cts,

	encrypt = encrypt,
	decrypt = decrypt,

	gf128_mul_alpha = gf128_mul_alpha,
	sector_to_tweak = sector_to_tweak,
}
