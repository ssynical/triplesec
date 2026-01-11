--!native
--!strict
--!optimize 2

local SHA256 = require(script.Parent.SHA256)
local SHA512 = require(script.Parent.SHA512)
local Whirlpool = require(script.Parent.Whirlpool)

local table_create = table.create
local string_byte = string.byte
local bxor = bit32.bxor

export type ByteArray = { number }
export type HashAlgorithm = "SHA256" | "SHA512" | "Whirlpool"

export type HashModule = {
	BLOCK_SIZE: number,
	DIGEST_SIZE: number,
	hash: (data: ByteArray) -> ByteArray,
}

export type HMACState = {
	algorithm: HashAlgorithm,
	opad: ByteArray,
	innerData: ByteArray,
	blockSize: number,
}

local function get_hash_module(algorithm: HashAlgorithm): HashModule
	if algorithm == "SHA256" then return SHA256
	elseif algorithm == "SHA512" then return SHA512
	else return Whirlpool end
end

-- XOR byte arrays
local function xor_bytes(a: ByteArray, b: ByteArray): ByteArray
	local len = #a
	local result = table_create(len) :: ByteArray
	for i = 1, len do result[i] = bxor(a[i], b[i]) end
	return result
end

-- Pad or hash key to block size
local function prepare_key(key: ByteArray, hashModule: HashModule): ByteArray
	local blockSize = hashModule.BLOCK_SIZE
	local preparedKey: ByteArray

	if #key > blockSize then
		preparedKey = hashModule.hash(key)
	else
		preparedKey = table_create(#key) :: ByteArray
		for i = 1, #key do preparedKey[i] = key[i] end
	end

	-- Pad with zeros to block size
	local padded = table_create(blockSize) :: ByteArray
	for i = 1, blockSize do padded[i] = preparedKey[i] or 0 end

	return padded
end

-- Create HMAC pads
local function create_pads(key: ByteArray, blockSize: number): (ByteArray, ByteArray)
	local ipad = table_create(blockSize) :: ByteArray
	local opad = table_create(blockSize) :: ByteArray

	for i = 1, blockSize do
		ipad[i] = bxor(key[i], 0x36)
		opad[i] = bxor(key[i], 0x5C)
	end

	return ipad, opad
end

-- Concatenate byte arrays
local function concat_bytes(a: ByteArray, b: ByteArray): ByteArray
	local lenA, lenB = #a, #b
	local result = table_create(lenA + lenB) :: ByteArray
	for i = 1, lenA do result[i] = a[i] end
	for i = 1, lenB do result[lenA + i] = b[i] end
	return result
end

-- HMAC computation
local function hmac(algorithm: HashAlgorithm, key: ByteArray, message: ByteArray): ByteArray
	local hashModule = get_hash_module(algorithm)
	local preparedKey = prepare_key(key, hashModule)
	local ipad, opad = create_pads(preparedKey, hashModule.BLOCK_SIZE)

	-- H(K XOR ipad || message)
	local innerInput = concat_bytes(ipad, message)
	local innerHash = hashModule.hash(innerInput)

	-- H(K XOR opad || inner_hash)
	local outerInput = concat_bytes(opad, innerHash)
	return hashModule.hash(outerInput)
end

-- HMAC with string key
local function hmac_string_key(algorithm: HashAlgorithm, key: string, message: ByteArray): ByteArray
	local keyBytes = table_create(#key) :: ByteArray
	for i = 1, #key do keyBytes[i] = string_byte(key, i) end
	return hmac(algorithm, keyBytes, message)
end

-- HMAC with string message
local function hmac_string_message(algorithm: HashAlgorithm, key: ByteArray, message: string): ByteArray
	local messageBytes = table_create(#message) :: ByteArray
	for i = 1, #message do messageBytes[i] = string_byte(message, i) end
	return hmac(algorithm, key, messageBytes)
end

-- HMAC with both string key and message
local function hmac_strings(algorithm: HashAlgorithm, key: string, message: string): ByteArray
	local keyBytes = table_create(#key) :: ByteArray
	for i = 1, #key do keyBytes[i] = string_byte(key, i) end
	local messageBytes = table_create(#message) :: ByteArray
	for i = 1, #message do messageBytes[i] = string_byte(message, i) end
	return hmac(algorithm, keyBytes, messageBytes)
end

-- HMAC -> hex string
local function hmac_hex(algorithm: HashAlgorithm, key: ByteArray, message: ByteArray): string
	local result = hmac(algorithm, key, message)
	local hex = table_create(#result)
	for i = 1, #result do hex[i] = string.format("%02x", result[i]) end
	return table.concat(hex)
end

local function create_state(algorithm: HashAlgorithm, key: ByteArray): HMACState
	local hashModule = get_hash_module(algorithm)
	local preparedKey = prepare_key(key, hashModule)
	local ipad, opad = create_pads(preparedKey, hashModule.BLOCK_SIZE)

	return {
		algorithm = algorithm,
		opad = opad,
		innerData = table.clone(ipad),
		blockSize = hashModule.BLOCK_SIZE,
	}
end

local function update(state: HMACState, data: ByteArray): ()
	local currentLen = #state.innerData
	for i = 1, #data do state.innerData[currentLen + i] = data[i] end
end

local function finalize(state: HMACState): ByteArray
	local hashModule = get_hash_module(state.algorithm)
	local innerHash = hashModule.hash(state.innerData)
	local outerInput = concat_bytes(state.opad, innerHash)
	return hashModule.hash(outerInput)
end

local function hmac_sha256(key: ByteArray, message: ByteArray): ByteArray return hmac("SHA256", key, message) end
local function hmac_sha512(key: ByteArray, message: ByteArray): ByteArray return hmac("SHA512", key, message) end
local function hmac_whirlpool(key: ByteArray, message: ByteArray): ByteArray return hmac("Whirlpool", key, message) end

local function get_digest_size(algorithm: HashAlgorithm): number
	if algorithm == "SHA256" then return 32
	else return 64 end
end

local function get_block_size(algorithm: HashAlgorithm): number
	if algorithm == "SHA256" then return 64
	else return 128 end
end

return {
	hmac = hmac,
	hmac_string_key = hmac_string_key,
	hmac_string_message = hmac_string_message,
	hmac_strings = hmac_strings,
	hmac_hex = hmac_hex,

	create_state = create_state,
	update = update,
	finalize = finalize,

	hmac_sha256 = hmac_sha256,
	hmac_sha512 = hmac_sha512,
	hmac_whirlpool = hmac_whirlpool,

	get_digest_size = get_digest_size,
	get_block_size = get_block_size,
	get_hash_module = get_hash_module,
}
