--!native
--!strict
--!optimize 2

local band, bxor = bit32.band, bit32.bxor
local lshift, rshift = bit32.lshift, bit32.rshift
local table_create = table.create
local string_byte = string.byte
local math_floor = math.floor

export type ByteArray = { number }
export type Word64 = { hi: number, lo: number }
export type HashState = {
	hash: { Word64 },
	length: number,
	buffer: ByteArray,
	bufferLength: number,
}

local WORD32_MAX: number = 0xFFFFFFFF
local ROUNDS: number = 10

local function w64(hi: number, lo: number): Word64 return { hi = hi, lo = lo } end
local function xor64(a: Word64, b: Word64): Word64 return { hi = bxor(a.hi, b.hi), lo = bxor(a.lo, b.lo) } end

local SBOX: { number } = {
	0x18, 0x23, 0xC6, 0xE8, 0x87, 0xB8, 0x01, 0x4F, 0x36, 0xA6, 0xD2, 0xF5, 0x79, 0x6F, 0x91, 0x52,
	0x60, 0xBC, 0x9B, 0x8E, 0xA3, 0x0C, 0x7B, 0x35, 0x1D, 0xE0, 0xD7, 0xC2, 0x2E, 0x4B, 0xFE, 0x57,
	0x15, 0x77, 0x37, 0xE5, 0x9F, 0xF0, 0x4A, 0xDA, 0x58, 0xC9, 0x29, 0x0A, 0xB1, 0xA0, 0x6B, 0x85,
	0xBD, 0x5D, 0x10, 0xF4, 0xCB, 0x3E, 0x05, 0x67, 0xE4, 0x27, 0x41, 0x8B, 0xA7, 0x7D, 0x95, 0xD8,
	0xFB, 0xEE, 0x7C, 0x66, 0xDD, 0x17, 0x47, 0x9E, 0xCA, 0x2D, 0xBF, 0x07, 0xAD, 0x5A, 0x83, 0x33,
	0x63, 0x02, 0xAA, 0x71, 0xC8, 0x19, 0x49, 0xD9, 0xF2, 0xE3, 0x5B, 0x88, 0x9A, 0x26, 0x32, 0xB0,
	0xE9, 0x0F, 0xD5, 0x80, 0xBE, 0xCD, 0x34, 0x48, 0xFF, 0x7A, 0x90, 0x5F, 0x20, 0x68, 0x1A, 0xAE,
	0xB4, 0x54, 0x93, 0x22, 0x64, 0xF1, 0x73, 0x12, 0x40, 0x08, 0xC3, 0xEC, 0xDB, 0xA1, 0x8D, 0x3D,
	0x97, 0x00, 0xCF, 0x2B, 0x76, 0x82, 0xD6, 0x1B, 0xB5, 0xAF, 0x6A, 0x50, 0x45, 0xF3, 0x30, 0xEF,
	0x3F, 0x55, 0xA2, 0xEA, 0x65, 0xBA, 0x2F, 0xC0, 0xDE, 0x1C, 0xFD, 0x4D, 0x92, 0x75, 0x06, 0x8A,
	0xB2, 0xE6, 0x0E, 0x1F, 0x62, 0xD4, 0xA8, 0x96, 0xF9, 0xC5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4C,
	0x5E, 0x78, 0x38, 0x8C, 0xD1, 0xA5, 0xE2, 0x61, 0xB3, 0x21, 0x9C, 0x1E, 0x43, 0xC7, 0xFC, 0x04,
	0x51, 0x99, 0x6D, 0x0D, 0xFA, 0xDF, 0x7E, 0x24, 0x3B, 0xAB, 0xCE, 0x11, 0x8F, 0x4E, 0xB7, 0xEB,
	0x3C, 0x81, 0x94, 0xF7, 0xB9, 0x13, 0x2C, 0xD3, 0xE7, 0x6E, 0xC4, 0x03, 0x56, 0x44, 0x7F, 0xA9,
	0x2A, 0xBB, 0xC1, 0x53, 0xDC, 0x0B, 0x9D, 0x6C, 0x31, 0x74, 0xF6, 0x46, 0xAC, 0x89, 0x14, 0xE1,
	0x16, 0x3A, 0x69, 0x09, 0x70, 0xB6, 0xD0, 0xED, 0xCC, 0x42, 0x98, 0xA4, 0x28, 0x5C, 0xF8, 0x86,
}

local C: { { number } } = {
	{ 0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09 },
	{ 0x09, 0x01, 0x01, 0x04, 0x01, 0x08, 0x05, 0x02 },
	{ 0x02, 0x09, 0x01, 0x01, 0x04, 0x01, 0x08, 0x05 },
	{ 0x05, 0x02, 0x09, 0x01, 0x01, 0x04, 0x01, 0x08 },
	{ 0x08, 0x05, 0x02, 0x09, 0x01, 0x01, 0x04, 0x01 },
	{ 0x01, 0x08, 0x05, 0x02, 0x09, 0x01, 0x01, 0x04 },
	{ 0x04, 0x01, 0x08, 0x05, 0x02, 0x09, 0x01, 0x01 },
	{ 0x01, 0x04, 0x01, 0x08, 0x05, 0x02, 0x09, 0x01 },
}

local RC: { { Word64 } } = {}

local function gf_mul(a: number, b: number): number
	local p = 0
	for _ = 1, 8 do
		if band(b, 1) ~= 0 then p = bxor(p, a) end
		local hi = band(a, 0x80)
		a = band(lshift(a, 1), 0xFF)
		if hi ~= 0 then a = bxor(a, 0x1D) end
		b = rshift(b, 1)
	end
	return p
end

local C0: { Word64 } = table_create(256) :: { Word64 }
local C1: { Word64 } = table_create(256) :: { Word64 }
local C2: { Word64 } = table_create(256) :: { Word64 }
local C3: { Word64 } = table_create(256) :: { Word64 }
local C4: { Word64 } = table_create(256) :: { Word64 }
local C5: { Word64 } = table_create(256) :: { Word64 }
local C6: { Word64 } = table_create(256) :: { Word64 }
local C7: { Word64 } = table_create(256) :: { Word64 }

local function init_tables(): ()
	for x = 0, 255 do
		local s = SBOX[x + 1]
		local v: { number } = table_create(8) :: { number }
		for i = 1, 8 do v[i] = gf_mul(s, C[i][1]) end

		C0[x] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }

		for i = 1, 8 do v[i] = gf_mul(s, C[i][2]) end
		C1[x] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }

		for i = 1, 8 do v[i] = gf_mul(s, C[i][3]) end
		C2[x] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }

		for i = 1, 8 do v[i] = gf_mul(s, C[i][4]) end
		C3[x] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }

		for i = 1, 8 do v[i] = gf_mul(s, C[i][5]) end
		C4[x] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }

		for i = 1, 8 do v[i] = gf_mul(s, C[i][6]) end
		C5[x] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }

		for i = 1, 8 do v[i] = gf_mul(s, C[i][7]) end
		C6[x] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }

		for i = 1, 8 do v[i] = gf_mul(s, C[i][8]) end
		C7[x] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }
	end

	for r = 1, ROUNDS do
		RC[r] = table_create(8) :: { Word64 }
		for i = 1, 8 do
			local idx = 8 * (r - 1) + (i - 1)
			local s = SBOX[idx + 1]
			local v: { number } = table_create(8) :: { number }
			for j = 1, 8 do v[j] = gf_mul(s, C[j][1]) end
			RC[r][i] = { hi = bxor(bxor(lshift(v[1], 24), lshift(v[2], 16)), bxor(lshift(v[3], 8), v[4])), lo = bxor(bxor(lshift(v[5], 24), lshift(v[6], 16)), bxor(lshift(v[7], 8), v[8])) }
		end
	end
end

local function get_byte(w: Word64, pos: number): number
	if pos < 4 then return band(rshift(w.hi, (3 - pos) * 8), 0xFF)
	else return band(rshift(w.lo, (7 - pos) * 8), 0xFF) end
end

local function xor64_8(a: Word64, b: Word64, c: Word64, d: Word64, e: Word64, f: Word64, g: Word64, h: Word64): Word64
	return {
		hi = bxor(bxor(bxor(a.hi, b.hi), bxor(c.hi, d.hi)), bxor(bxor(e.hi, f.hi), bxor(g.hi, h.hi))),
		lo = bxor(bxor(bxor(a.lo, b.lo), bxor(c.lo, d.lo)), bxor(bxor(e.lo, f.lo), bxor(g.lo, h.lo)))
	}
end

local function process_block(hash: { Word64 }, block: ByteArray, offset: number): ()
	local state: { Word64 } = table_create(8) :: { Word64 }
	local K: { Word64 } = table_create(8) :: { Word64 }

	for i = 1, 8 do
		local j = offset + (i - 1) * 8
		local hi = bxor(bxor(lshift(block[j], 24), lshift(block[j + 1], 16)), bxor(lshift(block[j + 2], 8), block[j + 3]))
		local lo = bxor(bxor(lshift(block[j + 4], 24), lshift(block[j + 5], 16)), bxor(lshift(block[j + 6], 8), block[j + 7]))
		state[i] = xor64({ hi = hi, lo = lo }, hash[i])
		K[i] = { hi = hash[i].hi, lo = hash[i].lo }
	end

	for r = 1, ROUNDS do
		local L: { Word64 } = table_create(8) :: { Word64 }
		for i = 1, 8 do
			L[i] = xor64_8(
				C0[get_byte(K[1], (i - 1) % 8)],
				C1[get_byte(K[2], (i) % 8)],
				C2[get_byte(K[3], (i + 1) % 8)],
				C3[get_byte(K[4], (i + 2) % 8)],
				C4[get_byte(K[5], (i + 3) % 8)],
				C5[get_byte(K[6], (i + 4) % 8)],
				C6[get_byte(K[7], (i + 5) % 8)],
				C7[get_byte(K[8], (i + 6) % 8)]
			)
		end
		L[1] = xor64(L[1], RC[r][1])
		for i = 1, 8 do K[i] = L[i] end

		for i = 1, 8 do
			L[i] = xor64(xor64_8(
				C0[get_byte(state[1], (i - 1) % 8)],
				C1[get_byte(state[2], (i) % 8)],
				C2[get_byte(state[3], (i + 1) % 8)],
				C3[get_byte(state[4], (i + 2) % 8)],
				C4[get_byte(state[5], (i + 3) % 8)],
				C5[get_byte(state[6], (i + 4) % 8)],
				C6[get_byte(state[7], (i + 5) % 8)],
				C7[get_byte(state[8], (i + 6) % 8)]
				), K[i])
		end
		for i = 1, 8 do state[i] = L[i] end
	end

	for i = 1, 8 do
		local j = offset + (i - 1) * 8
		local hi = bxor(bxor(lshift(block[j], 24), lshift(block[j + 1], 16)), bxor(lshift(block[j + 2], 8), block[j + 3]))
		local lo = bxor(bxor(lshift(block[j + 4], 24), lshift(block[j + 5], 16)), bxor(lshift(block[j + 6], 8), block[j + 7]))
		hash[i] = xor64(xor64(state[i], { hi = hi, lo = lo }), hash[i])
	end
end

init_tables()

local function create_state(): HashState
	return {
		hash = { w64(0, 0), w64(0, 0), w64(0, 0), w64(0, 0), w64(0, 0), w64(0, 0), w64(0, 0), w64(0, 0) },
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
			process_block(state.hash, state.buffer, 1)
			state.bufferLength = 0
		end
	end

	while dataIdx + 63 <= dataLen do
		process_block(state.hash, data, dataIdx)
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

	state.bufferLength = state.bufferLength + 1
	state.buffer[state.bufferLength] = 0x80

	if state.bufferLength > 32 then
		while state.bufferLength < 64 do
			state.bufferLength = state.bufferLength + 1
			state.buffer[state.bufferLength] = 0
		end
		process_block(state.hash, state.buffer, 1)
		state.bufferLength = 0
	end

	while state.bufferLength < 32 do
		state.bufferLength = state.bufferLength + 1
		state.buffer[state.bufferLength] = 0
	end

	for i = 33, 56 do state.buffer[i] = 0 end
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

	process_block(state.hash, state.buffer, 1)

	local digest = table_create(64) :: ByteArray
	for i = 1, 8 do
		local w, j = state.hash[i], (i - 1) * 8
		digest[j + 1] = band(rshift(w.hi, 24), 0xFF)
		digest[j + 2] = band(rshift(w.hi, 16), 0xFF)
		digest[j + 3] = band(rshift(w.hi, 8), 0xFF)
		digest[j + 4] = band(w.hi, 0xFF)
		digest[j + 5] = band(rshift(w.lo, 24), 0xFF)
		digest[j + 6] = band(rshift(w.lo, 16), 0xFF)
		digest[j + 7] = band(rshift(w.lo, 8), 0xFF)
		digest[j + 8] = band(w.lo, 0xFF)
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
	local hex = table_create(64)
	for i = 1, 64 do hex[i] = string.format("%02x", digest[i]) end
	return table.concat(hex)
end

local function hash_string_hex(str: string): string
	local bytes = table_create(#str) :: ByteArray
	for i = 1, #str do bytes[i] = string_byte(str, i) end
	return hash_hex(bytes)
end

local BLOCK_SIZE: number = 64
local DIGEST_SIZE: number = 64

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