--!native
--!strict
--!optimize 2

local HMAC = require(script.Parent.HMAC)

local table_create = table.create
local string_byte = string.byte
local bxor = bit32.bxor
local band, rshift = bit32.band, bit32.rshift

export type ByteArray = { number }
export type HashAlgorithm = "SHA256" | "SHA512" | "Whirlpool"

-- Veracrypt standards at 500,000 for SHA-512
local DEFAULT_ITERATIONS: { [HashAlgorithm]: number } = {
	SHA256 = 500000,
	SHA512 = 500000,
	Whirlpool = 500000,
}

local function xor_bytes_inplace(a: ByteArray, b: ByteArray): ()
	for i = 1, #a do a[i] = bxor(a[i], b[i]) end
end

local function concat_bytes(a: ByteArray, b: ByteArray): ByteArray
	local lenA, lenB = #a, #b
	local result = table_create(lenA + lenB) :: ByteArray
	for i = 1, lenA do result[i] = a[i] end
	for i = 1, lenB do result[lenA + i] = b[i] end
	return result
end

local function int_to_bytes(n: number): ByteArray
	return {
		band(rshift(n, 24), 0xFF),
		band(rshift(n, 16), 0xFF),
		band(rshift(n, 8), 0xFF),
		band(n, 0xFF),
	}
end

-- PBKDF2 F function (single block derivation)
local function pbkdf2_f(algorithm: HashAlgorithm, password: ByteArray, salt: ByteArray, iterations: number, blockIndex: number): ByteArray
	-- U1 = PRF(Password, Salt || INT(i))
	local saltWithIndex = concat_bytes(salt, int_to_bytes(blockIndex))
	local u = HMAC.hmac(algorithm, password, saltWithIndex)
	local result = table.clone(u)

	-- U2 ... Uc
	for _ = 2, iterations do
		u = HMAC.hmac(algorithm, password, u)
		xor_bytes_inplace(result, u)
	end

	return result
end

-- Main
local function derive(algorithm: HashAlgorithm, password: ByteArray, salt: ByteArray, iterations: number?, keyLength: number?): ByteArray
	local iters = iterations or DEFAULT_ITERATIONS[algorithm]
	local digestSize = HMAC.get_digest_size(algorithm)
	local dkLen = keyLength or digestSize

	local blockCount = math.ceil(dkLen / digestSize)

	local derivedKey = table_create(dkLen) :: ByteArray
	local offset = 0

	for i = 1, blockCount do
		local block = pbkdf2_f(algorithm, password, salt, iters, i)
		local copyLen = if i == blockCount then dkLen - offset else digestSize

		for j = 1, copyLen do derivedKey[offset + j] = block[j] end
		offset = offset + copyLen
	end

	return derivedKey
end

-- PBKDF2 with string password
local function derive_from_string(algorithm: HashAlgorithm, password: string, salt: ByteArray, iterations: number?, keyLength: number?): ByteArray
	local passwordBytes = table_create(#password) :: ByteArray
	for i = 1, #password do passwordBytes[i] = string_byte(password, i) end
	return derive(algorithm, passwordBytes, salt, iterations, keyLength)
end

-- PBKDF2 with both string password and salt
local function derive_from_strings(algorithm: HashAlgorithm, password: string, salt: string, iterations: number?, keyLength: number?): ByteArray
	local passwordBytes = table_create(#password) :: ByteArray
	for i = 1, #password do passwordBytes[i] = string_byte(password, i) end
	local saltBytes = table_create(#salt) :: ByteArray
	for i = 1, #salt do saltBytes[i] = string_byte(salt, i) end
	return derive(algorithm, passwordBytes, saltBytes, iterations, keyLength)
end

-- Convenience functions for specific algorithms
local function derive_sha256(password: ByteArray, salt: ByteArray, iterations: number?, keyLength: number?): ByteArray
	return derive("SHA256", password, salt, iterations, keyLength)
end

local function derive_sha512(password: ByteArray, salt: ByteArray, iterations: number?, keyLength: number?): ByteArray
	return derive("SHA512", password, salt, iterations, keyLength)
end

local function derive_whirlpool(password: ByteArray, salt: ByteArray, iterations: number?, keyLength: number?): ByteArray
	return derive("Whirlpool", password, salt, iterations, keyLength)
end

-- Veracrypt-specific key derivation (derives header key + secondary key)
-- Returns: { headerKey: 64 bytes, secondaryKey: 64 bytes } for cascaded ciphers
local function derive_veracrypt_keys(algorithm: HashAlgorithm, password: ByteArray, salt: ByteArray, iterations: number?): { headerKey: ByteArray, secondaryKey: ByteArray }
	-- Veracrypt derives 128 bytes total for cascaded ciphers
	local fullKey = derive(algorithm, password, salt, iterations, 128)

	local headerKey = table_create(64) :: ByteArray
	local secondaryKey = table_create(64) :: ByteArray

	for i = 1, 64 do
		headerKey[i] = fullKey[i]
		secondaryKey[i] = fullKey[64 + i]
	end

	return { headerKey = headerKey, secondaryKey = secondaryKey }
end

local function derive_hex(algorithm: HashAlgorithm, password: ByteArray, salt: ByteArray, iterations: number?, keyLength: number?): string
	local key = derive(algorithm, password, salt, iterations, keyLength)
	local hex = table_create(#key)
	for i = 1, #key do hex[i] = string.format("%02x", key[i]) end
	return table.concat(hex)
end

local function get_default_iterations(algorithm: HashAlgorithm): number
	return DEFAULT_ITERATIONS[algorithm]
end

return {
	derive = derive,
	derive_from_string = derive_from_string,
	derive_from_strings = derive_from_strings,
	derive_hex = derive_hex,

	derive_sha256 = derive_sha256,
	derive_sha512 = derive_sha512,
	derive_whirlpool = derive_whirlpool,

	derive_veracrypt_keys = derive_veracrypt_keys,

	get_default_iterations = get_default_iterations,
	DEFAULT_ITERATIONS = DEFAULT_ITERATIONS,
}
