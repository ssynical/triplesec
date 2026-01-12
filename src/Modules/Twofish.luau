--!native
--!strict
--!optimize 2

local band, bor, bxor = bit32.band, bit32.bor, bit32.bxor
local lshift, rshift = bit32.lshift, bit32.rshift
local lrotate, rrotate = bit32.lrotate, bit32.rrotate
local table_create = table.create

export type ByteArray = { number }
export type TwofishKey = {
	sbox: { { number } },
	subkeys: { number },
}

local BLOCK_SIZE: number = 16
local KEY_SIZE: number = 32
local ROUNDS: number = 16

local RS: { { number } } = {
	{ 0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E },
	{ 0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5 },
	{ 0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19 },
	{ 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03 },
}

local MDS: { { number } } = {
	{ 0x01, 0xEF, 0x5B, 0x5B },
	{ 0x5B, 0xEF, 0xEF, 0x01 },
	{ 0xEF, 0x5B, 0x01, 0xEF },
	{ 0xEF, 0x01, 0xEF, 0x5B },
}

local Q0: { number } = {
	0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
	0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
	0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
	0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
	0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
	0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
	0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
	0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
	0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
	0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
	0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
	0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
	0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
	0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
	0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
	0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
}

local Q1: { number } = {
	0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
	0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
	0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
	0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
	0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
	0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
	0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
	0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
	0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
	0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
	0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
	0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
	0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
	0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
	0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
	0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91,
}

local function gf_mul_169(a: number, b: number): number
	local p = 0
	for _ = 1, 8 do
		if band(b, 1) ~= 0 then p = bxor(p, a) end
		local hi = band(a, 0x80)
		a = band(lshift(a, 1), 0xFF)
		if hi ~= 0 then a = bxor(a, 0x69) end
		b = rshift(b, 1)
	end
	return p
end

local function gf_mul_mds(a: number, b: number): number
	local p = 0
	for _ = 1, 8 do
		if band(b, 1) ~= 0 then p = bxor(p, a) end
		local hi = band(a, 0x80)
		a = band(lshift(a, 1), 0xFF)
		if hi ~= 0 then a = bxor(a, 0x4D) end
		b = rshift(b, 1)
	end
	return p
end

local function mds_multiply(x: { number }): number
	local y = table_create(4) :: { number }
	for i = 1, 4 do
		y[i] = 0
		for j = 1, 4 do y[i] = bxor(y[i], gf_mul_mds(MDS[i][j], x[j])) end
	end
	return bor(bor(y[1], lshift(y[2], 8)), bor(lshift(y[3], 16), lshift(y[4], 24)))
end

local function h_func(x: number, L: { number }, k: number): number
	local y = { band(x, 0xFF), band(rshift(x, 8), 0xFF), band(rshift(x, 16), 0xFF), band(rshift(x, 24), 0xFF) }

	if k == 4 then
		y[1] = bxor(Q1[y[1] + 1], band(L[4], 0xFF))
		y[2] = bxor(Q0[y[2] + 1], band(rshift(L[4], 8), 0xFF))
		y[3] = bxor(Q0[y[3] + 1], band(rshift(L[4], 16), 0xFF))
		y[4] = bxor(Q1[y[4] + 1], band(rshift(L[4], 24), 0xFF))
	end

	if k >= 3 then
		y[1] = bxor(Q1[y[1] + 1], band(L[3], 0xFF))
		y[2] = bxor(Q1[y[2] + 1], band(rshift(L[3], 8), 0xFF))
		y[3] = bxor(Q0[y[3] + 1], band(rshift(L[3], 16), 0xFF))
		y[4] = bxor(Q0[y[4] + 1], band(rshift(L[3], 24), 0xFF))
	end

	y[1] = Q1[bxor(Q0[bxor(Q0[y[1] + 1], band(L[2], 0xFF)) + 1], band(L[1], 0xFF)) + 1]
	y[2] = Q0[bxor(Q0[bxor(Q1[y[2] + 1], band(rshift(L[2], 8), 0xFF)) + 1], band(rshift(L[1], 8), 0xFF)) + 1]
	y[3] = Q1[bxor(Q1[bxor(Q0[y[3] + 1], band(rshift(L[2], 16), 0xFF)) + 1], band(rshift(L[1], 16), 0xFF)) + 1]
	y[4] = Q0[bxor(Q1[bxor(Q1[y[4] + 1], band(rshift(L[2], 24), 0xFF)) + 1], band(rshift(L[1], 24), 0xFF)) + 1]

	return mds_multiply(y)
end

local function rs_multiply(k: { number }): number
	local s = 0
	for i = 1, 8 do
		local b = k[i]
		for j = 1, 4 do s = bxor(s, lshift(gf_mul_169(RS[j][i], b), (j - 1) * 8)) end
	end
	return s
end

local function expand_key(key: ByteArray): TwofishKey
	local keyLen = #key
	if keyLen < KEY_SIZE then error(`Twofish requires {KEY_SIZE}-byte key, got {keyLen} bytes`) end

	local Me: { number } = table_create(4) :: { number }
	local Mo: { number } = table_create(4) :: { number }

	for i = 1, 4 do
		local j = (i - 1) * 8 + 1
		Me[i] = bor(bor(key[j], lshift(key[j + 1], 8)), bor(lshift(key[j + 2], 16), lshift(key[j + 3], 24)))
		Mo[i] = bor(bor(key[j + 4], lshift(key[j + 5], 8)), bor(lshift(key[j + 6], 16), lshift(key[j + 7], 24)))
	end

	local S: { number } = table_create(4) :: { number }
	for i = 1, 4 do
		local k = table_create(8) :: { number }
		local j = (4 - i) * 8 + 1
		for m = 1, 8 do k[m] = key[j + m - 1] end
		S[i] = rs_multiply(k)
	end

	local subkeys: { number } = table_create(40) :: { number }
	local rho = 0x01010101

	for i = 0, 19 do
		local A = h_func(i * 2 * rho, Me, 4)
		local B = lrotate(h_func(i * 2 * rho + rho, Mo, 4), 8)
		subkeys[i * 2 + 1] = band(A + B, 0xFFFFFFFF)
		subkeys[i * 2 + 2] = lrotate(band(A + 2 * B, 0xFFFFFFFF), 9)
	end

	local sbox: { { number } } = { table_create(256) :: { number }, table_create(256) :: { number }, table_create(256) :: { number }, table_create(256) :: { number } }

	for i = 0, 255 do
		local x = { i, i, i, i }

		x[1] = Q1[bxor(Q0[bxor(Q0[bxor(Q1[x[1] + 1], band(S[4], 0xFF)) + 1], band(S[3], 0xFF)) + 1], band(S[2], 0xFF)) + 1]
		x[2] = Q0[bxor(Q0[bxor(Q1[bxor(Q1[x[2] + 1], band(rshift(S[4], 8), 0xFF)) + 1], band(rshift(S[3], 8), 0xFF)) + 1], band(rshift(S[2], 8), 0xFF)) + 1]
		x[3] = Q1[bxor(Q1[bxor(Q0[bxor(Q0[x[3] + 1], band(rshift(S[4], 16), 0xFF)) + 1], band(rshift(S[3], 16), 0xFF)) + 1], band(rshift(S[2], 16), 0xFF)) + 1]
		x[4] = Q0[bxor(Q1[bxor(Q1[bxor(Q0[x[4] + 1], band(rshift(S[4], 24), 0xFF)) + 1], band(rshift(S[3], 24), 0xFF)) + 1], band(rshift(S[2], 24), 0xFF)) + 1]

		x[1] = bxor(x[1], band(S[1], 0xFF))
		x[2] = bxor(x[2], band(rshift(S[1], 8), 0xFF))
		x[3] = bxor(x[3], band(rshift(S[1], 16), 0xFF))
		x[4] = bxor(x[4], band(rshift(S[1], 24), 0xFF))

		local mds_out = mds_multiply(x)
		sbox[1][i] = band(mds_out, 0xFF)
		sbox[2][i] = band(rshift(mds_out, 8), 0xFF)
		sbox[3][i] = band(rshift(mds_out, 16), 0xFF)
		sbox[4][i] = band(rshift(mds_out, 24), 0xFF)
	end

	return { sbox = sbox, subkeys = subkeys }
end

local function g_func(x: number, sbox: { { number } }): number
	return bor(
		bor(sbox[1][band(x, 0xFF)], lshift(sbox[2][band(rshift(x, 8), 0xFF)], 8)),
		bor(lshift(sbox[3][band(rshift(x, 16), 0xFF)], 16), lshift(sbox[4][band(rshift(x, 24), 0xFF)], 24))
	)
end

local function encrypt_block(key: TwofishKey, input: ByteArray, inputOffset: number?, output: ByteArray?, outputOffset: number?): ByteArray
	local inOff = inputOffset or 1
	local outOff = outputOffset or 1
	local out = output or (table_create(16) :: ByteArray)
	local sbox, sk = key.sbox, key.subkeys

	local x0: number = bxor(bor(bor(input[inOff], lshift(input[inOff + 1], 8)), bor(lshift(input[inOff + 2], 16), lshift(input[inOff + 3], 24))), sk[1])
	local x1: number = bxor(bor(bor(input[inOff + 4], lshift(input[inOff + 5], 8)), bor(lshift(input[inOff + 6], 16), lshift(input[inOff + 7], 24))), sk[2])
	local x2: number = bxor(bor(bor(input[inOff + 8], lshift(input[inOff + 9], 8)), bor(lshift(input[inOff + 10], 16), lshift(input[inOff + 11], 24))), sk[3])
	local x3: number = bxor(bor(bor(input[inOff + 12], lshift(input[inOff + 13], 8)), bor(lshift(input[inOff + 14], 16), lshift(input[inOff + 15], 24))), sk[4])

	for r = 0, 15 do
		local t0 = g_func(x0, sbox)
		local t1 = g_func(lrotate(x1, 8), sbox)
		local f0 = band(t0 + t1 + sk[r * 2 + 9], 0xFFFFFFFF)
		local f1 = band(t0 + 2 * t1 + sk[r * 2 + 10], 0xFFFFFFFF)

		local tmp = x0
		x0 = rrotate(bxor(x2, f0), 1)
		x2 = tmp
		tmp = x1
		x1 = bxor(lrotate(x3, 1), f1)
		x3 = tmp
	end

	local y0 = bxor(x2, sk[5])
	local y1 = bxor(x3, sk[6])
	local y2 = bxor(x0, sk[7])
	local y3 = bxor(x1, sk[8])

	out[outOff] = band(y0, 0xFF); out[outOff + 1] = band(rshift(y0, 8), 0xFF); out[outOff + 2] = band(rshift(y0, 16), 0xFF); out[outOff + 3] = band(rshift(y0, 24), 0xFF)
	out[outOff + 4] = band(y1, 0xFF); out[outOff + 5] = band(rshift(y1, 8), 0xFF); out[outOff + 6] = band(rshift(y1, 16), 0xFF); out[outOff + 7] = band(rshift(y1, 24), 0xFF)
	out[outOff + 8] = band(y2, 0xFF); out[outOff + 9] = band(rshift(y2, 8), 0xFF); out[outOff + 10] = band(rshift(y2, 16), 0xFF); out[outOff + 11] = band(rshift(y2, 24), 0xFF)
	out[outOff + 12] = band(y3, 0xFF); out[outOff + 13] = band(rshift(y3, 8), 0xFF); out[outOff + 14] = band(rshift(y3, 16), 0xFF); out[outOff + 15] = band(rshift(y3, 24), 0xFF)

	return out
end

local function decrypt_block(key: TwofishKey, input: ByteArray, inputOffset: number?, output: ByteArray?, outputOffset: number?): ByteArray
	local inOff = inputOffset or 1
	local outOff = outputOffset or 1
	local out = output or (table_create(16) :: ByteArray)
	local sbox, sk = key.sbox, key.subkeys

	local c0: number = bor(bor(input[inOff], lshift(input[inOff + 1], 8)), bor(lshift(input[inOff + 2], 16), lshift(input[inOff + 3], 24)))
	local c1: number = bor(bor(input[inOff + 4], lshift(input[inOff + 5], 8)), bor(lshift(input[inOff + 6], 16), lshift(input[inOff + 7], 24)))
	local c2: number = bor(bor(input[inOff + 8], lshift(input[inOff + 9], 8)), bor(lshift(input[inOff + 10], 16), lshift(input[inOff + 11], 24)))
	local c3: number = bor(bor(input[inOff + 12], lshift(input[inOff + 13], 8)), bor(lshift(input[inOff + 14], 16), lshift(input[inOff + 15], 24)))

	local x0 = bxor(c2, sk[7])
	local x1 = bxor(c3, sk[8])
	local x2 = bxor(c0, sk[5])
	local x3 = bxor(c1, sk[6])

	for r = 15, 0, -1 do
		-- x2 and x3 hold the original x0 and x1 from encrypt round
		local t0 = g_func(x2, sbox)
		local t1 = g_func(lrotate(x3, 8), sbox)
		local f0 = band(t0 + t1 + sk[r * 2 + 9], 0xFFFFFFFF)
		local f1 = band(t0 + 2 * t1 + sk[r * 2 + 10], 0xFFFFFFFF)

		-- new_x0 = rrotate(x2^f0, 1) => x2 = lrotate(new_x0, 1) ^ f0
		-- new_x2 = old_x0 => old_x0 = new_x2
		local tmp = x0
		x0 = x2
		x2 = bxor(lrotate(tmp, 1), f0)

		-- new_x1 = lrotate(x3, 1) ^ f1 => x3 = rrotate(new_x1 ^ f1, 1)
		-- new_x3 = old_x1 => old_x1 = new_x3
		tmp = x1
		x1 = x3
		x3 = rrotate(bxor(tmp, f1), 1)
	end

	local y0 = bxor(x0, sk[1])
	local y1 = bxor(x1, sk[2])
	local y2 = bxor(x2, sk[3])
	local y3 = bxor(x3, sk[4])

	out[outOff] = band(y0, 0xFF); out[outOff + 1] = band(rshift(y0, 8), 0xFF); out[outOff + 2] = band(rshift(y0, 16), 0xFF); out[outOff + 3] = band(rshift(y0, 24), 0xFF)
	out[outOff + 4] = band(y1, 0xFF); out[outOff + 5] = band(rshift(y1, 8), 0xFF); out[outOff + 6] = band(rshift(y1, 16), 0xFF); out[outOff + 7] = band(rshift(y1, 24), 0xFF)
	out[outOff + 8] = band(y2, 0xFF); out[outOff + 9] = band(rshift(y2, 8), 0xFF); out[outOff + 10] = band(rshift(y2, 16), 0xFF); out[outOff + 11] = band(rshift(y2, 24), 0xFF)
	out[outOff + 12] = band(y3, 0xFF); out[outOff + 13] = band(rshift(y3, 8), 0xFF); out[outOff + 14] = band(rshift(y3, 16), 0xFF); out[outOff + 15] = band(rshift(y3, 24), 0xFF)

	return out
end

return {
	BLOCK_SIZE = BLOCK_SIZE,
	KEY_SIZE = KEY_SIZE,
	ROUNDS = ROUNDS,

	expand_key = expand_key,

	encrypt_block = encrypt_block,
	decrypt_block = decrypt_block,
}