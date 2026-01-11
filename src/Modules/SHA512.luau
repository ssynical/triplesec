--!native
--!strict
--!optimize 2

local band, bxor, bnot = bit32.band, bit32.bxor, bit32.bnot
local lshift, rshift = bit32.lshift, bit32.rshift
local table_create = table.create
local string_byte = string.byte
local math_floor = math.floor

export type ByteArray = { number }
export type Word64 = { hi: number, lo: number }
export type HashState = {
	h: { Word64 },
	length: number,
	buffer: ByteArray,
	bufferLength: number,
}

local WORD32_MAX: number = 0xFFFFFFFF

local function w64(hi: number, lo: number): Word64 return { hi = hi, lo = lo } end

local function xor64(a: Word64, b: Word64): Word64 return { hi = bxor(a.hi, b.hi), lo = bxor(a.lo, b.lo) } end
local function xor64_3(a: Word64, b: Word64, c: Word64): Word64 return { hi = bxor(bxor(a.hi, b.hi), c.hi), lo = bxor(bxor(a.lo, b.lo), c.lo) } end
local function and64(a: Word64, b: Word64): Word64 return { hi = band(a.hi, b.hi), lo = band(a.lo, b.lo) } end
local function not64(a: Word64): Word64 return { hi = band(bnot(a.hi), WORD32_MAX), lo = band(bnot(a.lo), WORD32_MAX) } end

local function add64(a: Word64, b: Word64): Word64
	local lo = a.lo + b.lo
	local carry = if lo > WORD32_MAX then 1 else 0
	return { hi = band(a.hi + b.hi + carry, WORD32_MAX), lo = band(lo, WORD32_MAX) }
end

local function add64_5(a: Word64, b: Word64, c: Word64, d: Word64, e: Word64): Word64
	return add64(add64(add64(add64(a, b), c), d), e)
end

local function shr64(a: Word64, n: number): Word64
	if n >= 64 then return { hi = 0, lo = 0 }
	elseif n >= 32 then return { hi = 0, lo = rshift(a.hi, n - 32) }
	elseif n == 0 then return { hi = a.hi, lo = a.lo }
	else return { hi = rshift(a.hi, n), lo = bxor(rshift(a.lo, n), lshift(a.hi, 32 - n)) } end
end

local function ror64(a: Word64, n: number): Word64
	n = n % 64
	if n == 0 then return { hi = a.hi, lo = a.lo }
	elseif n == 32 then return { hi = a.lo, lo = a.hi }
	elseif n < 32 then return { hi = bxor(rshift(a.hi, n), lshift(a.lo, 32 - n)), lo = bxor(rshift(a.lo, n), lshift(a.hi, 32 - n)) }
	else n = n - 32; return { hi = bxor(rshift(a.lo, n), lshift(a.hi, 32 - n)), lo = bxor(rshift(a.hi, n), lshift(a.lo, 32 - n)) } end
end

-- SHA-512 round constants (first 64 bits of fractional parts of cube roots of first 80 primes)
local K: { Word64 } = {
	w64(0x428A2F98, 0xD728AE22), w64(0x71374491, 0x23EF65CD), w64(0xB5C0FBCF, 0xEC4D3B2F), w64(0xE9B5DBA5, 0x8189DBBC),
	w64(0x3956C25B, 0xF348B538), w64(0x59F111F1, 0xB605D019), w64(0x923F82A4, 0xAF194F9B), w64(0xAB1C5ED5, 0xDA6D8118),
	w64(0xD807AA98, 0xA3030242), w64(0x12835B01, 0x45706FBE), w64(0x243185BE, 0x4EE4B28C), w64(0x550C7DC3, 0xD5FFB4E2),
	w64(0x72BE5D74, 0xF27B896F), w64(0x80DEB1FE, 0x3B1696B1), w64(0x9BDC06A7, 0x25C71235), w64(0xC19BF174, 0xCF692694),
	w64(0xE49B69C1, 0x9EF14AD2), w64(0xEFBE4786, 0x384F25E3), w64(0x0FC19DC6, 0x8B8CD5B5), w64(0x240CA1CC, 0x77AC9C65),
	w64(0x2DE92C6F, 0x592B0275), w64(0x4A7484AA, 0x6EA6E483), w64(0x5CB0A9DC, 0xBD41FBD4), w64(0x76F988DA, 0x831153B5),
	w64(0x983E5152, 0xEE66DFAB), w64(0xA831C66D, 0x2DB43210), w64(0xB00327C8, 0x98FB213F), w64(0xBF597FC7, 0xBEEF0EE4),
	w64(0xC6E00BF3, 0x3DA88FC2), w64(0xD5A79147, 0x930AA725), w64(0x06CA6351, 0xE003826F), w64(0x14292967, 0x0A0E6E70),
	w64(0x27B70A85, 0x46D22FFC), w64(0x2E1B2138, 0x5C26C926), w64(0x4D2C6DFC, 0x5AC42AED), w64(0x53380D13, 0x9D95B3DF),
	w64(0x650A7354, 0x8BAF63DE), w64(0x766A0ABB, 0x3C77B2A8), w64(0x81C2C92E, 0x47EDAEE6), w64(0x92722C85, 0x1482353B),
	w64(0xA2BFE8A1, 0x4CF10364), w64(0xA81A664B, 0xBC423001), w64(0xC24B8B70, 0xD0F89791), w64(0xC76C51A3, 0x0654BE30),
	w64(0xD192E819, 0xD6EF5218), w64(0xD6990624, 0x5565A910), w64(0xF40E3585, 0x5771202A), w64(0x106AA070, 0x32BBD1B8),
	w64(0x19A4C116, 0xB8D2D0C8), w64(0x1E376C08, 0x5141AB53), w64(0x2748774C, 0xDF8EEB99), w64(0x34B0BCB5, 0xE19B48A8),
	w64(0x391C0CB3, 0xC5C95A63), w64(0x4ED8AA4A, 0xE3418ACB), w64(0x5B9CCA4F, 0x7763E373), w64(0x682E6FF3, 0xD6B2B8A3),
	w64(0x748F82EE, 0x5DEFB2FC), w64(0x78A5636F, 0x43172F60), w64(0x84C87814, 0xA1F0AB72), w64(0x8CC70208, 0x1A6439EC),
	w64(0x90BEFFFA, 0x23631E28), w64(0xA4506CEB, 0xDE82BDE9), w64(0xBEF9A3F7, 0xB2C67915), w64(0xC67178F2, 0xE372532B),
	w64(0xCA273ECE, 0xEA26619C), w64(0xD186B8C7, 0x21C0C207), w64(0xEADA7DD6, 0xCDE0EB1E), w64(0xF57D4F7F, 0xEE6ED178),
	w64(0x06F067AA, 0x72176FBA), w64(0x0A637DC5, 0xA2C898A6), w64(0x113F9804, 0xBEF90DAE), w64(0x1B710B35, 0x131C471B),
	w64(0x28DB77F5, 0x23047D84), w64(0x32CAAB7B, 0x40C72493), w64(0x3C9EBE0A, 0x15C9BEBC), w64(0x431D67C4, 0x9C100D4C),
	w64(0x4CC5D4BE, 0xCB3E42B6), w64(0x597F299C, 0xFC657E2A), w64(0x5FCB6FAB, 0x3AD6FAEC), w64(0x6C44198C, 0x4A475817),
}

-- Initial hash values (first 64 bits of fractional parts of square roots of first 8 primes)
local H0: { Word64 } = {
	w64(0x6A09E667, 0xF3BCC908), w64(0xBB67AE85, 0x84CAA73B), w64(0x3C6EF372, 0xFE94F82B), w64(0xA54FF53A, 0x5F1D36F1),
	w64(0x510E527F, 0xADE682D1), w64(0x9B05688C, 0x2B3E6C1F), w64(0x1F83D9AB, 0xFB41BD6B), w64(0x5BE0CD19, 0x137E2179),
}

local function ch(x: Word64, y: Word64, z: Word64): Word64 return xor64(and64(x, y), and64(not64(x), z)) end
local function maj(x: Word64, y: Word64, z: Word64): Word64 return xor64_3(and64(x, y), and64(x, z), and64(y, z)) end
local function sigma0(x: Word64): Word64 return xor64_3(ror64(x, 28), ror64(x, 34), ror64(x, 39)) end
local function sigma1(x: Word64): Word64 return xor64_3(ror64(x, 14), ror64(x, 18), ror64(x, 41)) end
local function gamma0(x: Word64): Word64 return xor64_3(ror64(x, 1), ror64(x, 8), shr64(x, 7)) end
local function gamma1(x: Word64): Word64 return xor64_3(ror64(x, 19), ror64(x, 61), shr64(x, 6)) end

local function process_block(h: { Word64 }, block: ByteArray, offset: number): ()
	local W: { Word64 } = table_create(80) :: { Word64 }

	for i = 1, 16 do
		local j = offset + (i - 1) * 8
		W[i] = {
			hi = bxor(bxor(lshift(block[j], 24), lshift(block[j + 1], 16)), bxor(lshift(block[j + 2], 8), block[j + 3])),
			lo = bxor(bxor(lshift(block[j + 4], 24), lshift(block[j + 5], 16)), bxor(lshift(block[j + 6], 8), block[j + 7]))
		}
	end

	for i = 17, 80 do
		local g0, g1 = gamma0(W[i - 15]), gamma1(W[i - 2])
		W[i] = add64(add64(add64(g1, W[i - 7]), g0), W[i - 16])
	end

	local a: Word64 = h[1]
	local b: Word64 = h[2]
	local c: Word64 = h[3]
	local d: Word64 = h[4]
	local e: Word64 = h[5]
	local f: Word64 = h[6]
	local g: Word64 = h[7]
	local hh: Word64 = h[8]

	for i = 1, 80 do
		local t1 = add64_5(hh, sigma1(e), ch(e, f, g), K[i], W[i])
		local t2 = add64(sigma0(a), maj(a, b, c))
		hh = g
		g = f
		f = e
		e = add64(d, t1)
		d = c
		c = b
		b = a
		a = add64(t1, t2)
	end

	h[1] = add64(h[1], a)
	h[2] = add64(h[2], b)
	h[3] = add64(h[3], c)
	h[4] = add64(h[4], d)
	h[5] = add64(h[5], e)
	h[6] = add64(h[6], f)
	h[7] = add64(h[7], g)
	h[8] = add64(h[8], hh)
end

local function create_state(): HashState
	return {
		h = {
			w64(H0[1].hi, H0[1].lo), w64(H0[2].hi, H0[2].lo), w64(H0[3].hi, H0[3].lo), w64(H0[4].hi, H0[4].lo),
			w64(H0[5].hi, H0[5].lo), w64(H0[6].hi, H0[6].lo), w64(H0[7].hi, H0[7].lo), w64(H0[8].hi, H0[8].lo),
		},
		length = 0,
		buffer = table_create(128) :: ByteArray,
		bufferLength = 0,
	}
end

local function update(state: HashState, data: ByteArray): ()
	local dataLen = #data
	local dataIdx = 1

	state.length = state.length + dataLen

	if state.bufferLength > 0 then
		local needed = 128 - state.bufferLength
		local toCopy = if dataLen < needed then dataLen else needed

		for i = 1, toCopy do state.buffer[state.bufferLength + i] = data[dataIdx + i - 1] end
		state.bufferLength = state.bufferLength + toCopy
		dataIdx = dataIdx + toCopy

		if state.bufferLength == 128 then
			process_block(state.h, state.buffer, 1)
			state.bufferLength = 0
		end
	end

	while dataIdx + 127 <= dataLen do
		process_block(state.h, data, dataIdx)
		dataIdx = dataIdx + 128
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

	-- Pad to 112 bytes (896 bits) mod 128
	if state.bufferLength > 112 then
		while state.bufferLength < 128 do
			state.bufferLength = state.bufferLength + 1
			state.buffer[state.bufferLength] = 0
		end
		process_block(state.h, state.buffer, 1)
		state.bufferLength = 0
	end

	while state.bufferLength < 112 do
		state.bufferLength = state.bufferLength + 1
		state.buffer[state.bufferLength] = 0
	end

	-- Append length in bits (big-endian, 128-bit, but we only use lower 64 bits)
	for i = 113, 120 do state.buffer[i] = 0 end
	local hiLen = math_floor(bitLength / 0x100000000)
	local loLen = bitLength % 0x100000000
	state.buffer[121] = band(rshift(hiLen, 24), 0xFF)
	state.buffer[122] = band(rshift(hiLen, 16), 0xFF)
	state.buffer[123] = band(rshift(hiLen, 8), 0xFF)
	state.buffer[124] = band(hiLen, 0xFF)
	state.buffer[125] = band(rshift(loLen, 24), 0xFF)
	state.buffer[126] = band(rshift(loLen, 16), 0xFF)
	state.buffer[127] = band(rshift(loLen, 8), 0xFF)
	state.buffer[128] = band(loLen, 0xFF)

	process_block(state.h, state.buffer, 1)

	local digest = table_create(64) :: ByteArray
	for i = 1, 8 do
		local w, j = state.h[i], (i - 1) * 8
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

local BLOCK_SIZE: number = 128
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
