--!native
--!strict
--!optimize 2

local band, bxor, bnot = bit32.band, bit32.bxor, bit32.bnot
local rshift, rrotate = bit32.rshift, bit32.rrotate
local table_create = table.create
local string_byte = string.byte
local math_floor = math.floor

export type ByteArray = { number }
export type HashState = {
	h: { number },
	length: number,
	buffer: ByteArray,
	bufferLength: number,
}

-- SHA-256 round constants (first 32 bits of fractional parts of cube roots of first 64 primes)
local K: { number } = {
	0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
	0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
	0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
	0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
	0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
	0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
	0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
	0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
}

-- Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
local H0: { number } = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

local function ch(x: number, y: number, z: number): number return bxor(band(x, y), band(bnot(x), z)) end
local function maj(x: number, y: number, z: number): number return bxor(bxor(band(x, y), band(x, z)), band(y, z)) end
local function sigma0(x: number): number return bxor(bxor(rrotate(x, 2), rrotate(x, 13)), rrotate(x, 22)) end
local function sigma1(x: number): number return bxor(bxor(rrotate(x, 6), rrotate(x, 11)), rrotate(x, 25)) end
local function gamma0(x: number): number return bxor(bxor(rrotate(x, 7), rrotate(x, 18)), rshift(x, 3)) end
local function gamma1(x: number): number return bxor(bxor(rrotate(x, 17), rrotate(x, 19)), rshift(x, 10)) end

local function process_block(h: { number }, block: ByteArray, offset: number): ()
	local W = table_create(64) :: { number }

	for i = 1, 16 do
		local j = offset + (i - 1) * 4
		W[i] = bit32.bor(bit32.bor(bit32.lshift(block[j], 24), bit32.lshift(block[j + 1], 16)), bit32.bor(bit32.lshift(block[j + 2], 8), block[j + 3]))
	end

	-- Extend to 64 words
	for i = 17, 64 do W[i] = band(gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16], 0xFFFFFFFF) end

	-- Initialise our working variables
	local a: number = h[1]
	local b: number = h[2]
	local c: number = h[3]
	local d: number = h[4]
	local e: number = h[5]
	local f: number = h[6]
	local g: number = h[7]
	local hh: number = h[8]

	-- Main loop
	for i = 1, 64 do
		local t1 = band(hh + sigma1(e) + ch(e, f, g) + K[i] + W[i], 0xFFFFFFFF)
		local t2 = band(sigma0(a) + maj(a, b, c), 0xFFFFFFFF)
		hh = g
		g = f
		f = e
		e = band(d + t1, 0xFFFFFFFF)
		d = c
		c = b
		b = a
		a = band(t1 + t2, 0xFFFFFFFF)
	end

	h[1] = band((h[1] :: number) + a, 0xFFFFFFFF)
	h[2] = band((h[2] :: number) + b, 0xFFFFFFFF)
	h[3] = band((h[3] :: number) + c, 0xFFFFFFFF)
	h[4] = band((h[4] :: number) + d, 0xFFFFFFFF)
	h[5] = band((h[5] :: number) + e, 0xFFFFFFFF)
	h[6] = band((h[6] :: number) + f, 0xFFFFFFFF)
	h[7] = band((h[7] :: number) + g, 0xFFFFFFFF)
	h[8] = band((h[8] :: number) + hh, 0xFFFFFFFF)
end

local function create_state(): HashState
	return {
		h = { H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7], H0[8] },
		length = 0,
		buffer = table_create(64) :: ByteArray,
		bufferLength = 0,
	}
end

local function update(state: HashState, data: ByteArray): ()
	local dataLen = #data
	local dataIdx = 1

	state.length = state.length + dataLen

	if state.bufferLength > 0 then
		local needed = 64 - state.bufferLength
		local toCopy = if dataLen < needed then dataLen else needed

		for i = 1, toCopy do state.buffer[state.bufferLength + i] = data[dataIdx + i - 1] end
		state.bufferLength = state.bufferLength + toCopy
		dataIdx = dataIdx + toCopy

		if state.bufferLength == 64 then
			process_block(state.h, state.buffer, 1)
			state.bufferLength = 0
		end
	end

	-- Process full blocks directly from data
	while dataIdx + 63 <= dataLen do
		process_block(state.h, data, dataIdx)
		dataIdx = dataIdx + 64
	end

	while dataIdx <= dataLen do
		state.bufferLength = state.bufferLength + 1
		state.buffer[state.bufferLength] = data[dataIdx]
		dataIdx = dataIdx + 1
	end
end

local function finalize(state: HashState): ByteArray
	local bitLength = state.length * 8

	-- Append padding bit
	state.bufferLength = state.bufferLength + 1
	state.buffer[state.bufferLength] = 0x80

	-- Pad to 56 bytes (448 bits) mod 64
	if state.bufferLength > 56 then
		while state.bufferLength < 64 do
			state.bufferLength = state.bufferLength + 1
			state.buffer[state.bufferLength] = 0
		end
		process_block(state.h, state.buffer, 1)
		state.bufferLength = 0
	end

	while state.bufferLength < 56 do
		state.bufferLength = state.bufferLength + 1
		state.buffer[state.bufferLength] = 0
	end

	-- Append length in bits (big-endian, 64-bit)
	local hiLen = math_floor(bitLength / 0x100000000)
	local loLen = bitLength % 0x100000000
	state.buffer[57] = band(rshift(hiLen, 24), 0xFF)
	state.buffer[58] = band(rshift(hiLen, 16), 0xFF)
	state.buffer[59] = band(rshift(hiLen, 8), 0xFF)
	state.buffer[60] = band(hiLen, 0xFF)
	state.buffer[61] = band(rshift(loLen, 24), 0xFF)
	state.buffer[62] = band(rshift(loLen, 16), 0xFF)
	state.buffer[63] = band(rshift(loLen, 8), 0xFF)
	state.buffer[64] = band(loLen, 0xFF)

	process_block(state.h, state.buffer, 1)

	local digest = table_create(32) :: ByteArray
	for i = 1, 8 do
		local w, j = state.h[i], (i - 1) * 4
		digest[j + 1] = band(rshift(w, 24), 0xFF)
		digest[j + 2] = band(rshift(w, 16), 0xFF)
		digest[j + 3] = band(rshift(w, 8), 0xFF)
		digest[j + 4] = band(w, 0xFF)
	end

	return digest
end

local function hash(data: ByteArray): ByteArray
	local state = create_state()
	update(state, data)
	return finalize(state)
end

local function hash_string(str: string): ByteArray
	local bytes = table_create(#str) :: ByteArray
	for i = 1, #str do bytes[i] = string_byte(str, i) end
	return hash(bytes)
end

local function hash_hex(data: ByteArray): string
	local digest = hash(data)
	local hex = table_create(32)
	for i = 1, 32 do hex[i] = string.format("%02x", digest[i]) end
	return table.concat(hex)
end

local function hash_string_hex(str: string): string
	local bytes = table_create(#str) :: ByteArray
	for i = 1, #str do bytes[i] = string_byte(str, i) end
	return hash_hex(bytes)
end

local BLOCK_SIZE: number = 64
local DIGEST_SIZE: number = 32

return {
	BLOCK_SIZE = BLOCK_SIZE,
	DIGEST_SIZE = DIGEST_SIZE,

	create_state = create_state,
	update = update,
	finalize = finalize,

	hash = hash,
	hash_string = hash_string,
	hash_hex = hash_hex,
	hash_string_hex = hash_string_hex,
}
