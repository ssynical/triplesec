--!native
--!strict
--!optimize 2

local band, bxor = bit32.band, bit32.bxor
local lshift, rshift = bit32.lshift, bit32.rshift
local table_create = table.create

export type ByteArray = { number }
export type AESKey = { roundKeys: { number }, decRoundKeys: { number }, rounds: number }

local BLOCK_SIZE: number = 16
local KEY_SIZE: number = 32
local ROUNDS: number = 14
local NK: number = 8
local NB: number = 4

-- AES S-box
local SBOX: { number } = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
}

-- Inverse S-box
local INV_SBOX: { number } = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
}

-- Round constants
local RCON: { number } = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 }

-- GF(2^8) multiplication
local function gf_mul(a: number, b: number): number
	local p = 0
	for _ = 1, 8 do
		if band(b, 1) ~= 0 then p = bxor(p, a) end
		local hi = band(a, 0x80)
		a = band(lshift(a, 1), 0xFF)
		if hi ~= 0 then a = bxor(a, 0x1B) end
		b = rshift(b, 1)
	end
	return p
end

-- Precomputed T-tables

-- encryption
local TE0: { number } = table_create(256) :: { number }
local TE1: { number } = table_create(256) :: { number }
local TE2: { number } = table_create(256) :: { number }
local TE3: { number } = table_create(256) :: { number }

-- decryption
local TD0: { number } = table_create(256) :: { number }
local TD1: { number } = table_create(256) :: { number }
local TD2: { number } = table_create(256) :: { number }
local TD3: { number } = table_create(256) :: { number }

local function init_tables(): ()
	for i = 0, 255 do
		local s = SBOX[i + 1]
		local s2 = gf_mul(s, 2)
		local s3 = gf_mul(s, 3)

		TE0[i] = bxor(bxor(lshift(s2, 24), lshift(s, 16)), bxor(lshift(s, 8), s3))
		TE1[i] = bxor(bxor(lshift(s3, 24), lshift(s2, 16)), bxor(lshift(s, 8), s))
		TE2[i] = bxor(bxor(lshift(s, 24), lshift(s3, 16)), bxor(lshift(s2, 8), s))
		TE3[i] = bxor(bxor(lshift(s, 24), lshift(s, 16)), bxor(lshift(s3, 8), s2))

		local si = INV_SBOX[i + 1]
		local si9 = gf_mul(si, 9)
		local siB = gf_mul(si, 11)
		local siD = gf_mul(si, 13)
		local siE = gf_mul(si, 14)

		TD0[i] = bxor(bxor(lshift(siE, 24), lshift(si9, 16)), bxor(lshift(siD, 8), siB))
		TD1[i] = bxor(bxor(lshift(siB, 24), lshift(siE, 16)), bxor(lshift(si9, 8), siD))
		TD2[i] = bxor(bxor(lshift(siD, 24), lshift(siB, 16)), bxor(lshift(siE, 8), si9))
		TD3[i] = bxor(bxor(lshift(si9, 24), lshift(siD, 16)), bxor(lshift(siB, 8), siE))
	end
end

init_tables()

local function inv_mix_column(w: number): number
	local b0 = band(rshift(w, 24), 0xFF)
	local b1 = band(rshift(w, 16), 0xFF)
	local b2 = band(rshift(w, 8), 0xFF)
	local b3 = band(w, 0xFF)

	return bxor(bxor(TD0[SBOX[b0 + 1]], TD1[SBOX[b1 + 1]]), bxor(TD2[SBOX[b2 + 1]], TD3[SBOX[b3 + 1]]))
end

local function expand_key(key: ByteArray): AESKey
	local w: { number } = table_create(60) :: { number }

	-- The first nk words are the key itself
	for i = 1, NK do
		local j = (i - 1) * 4 + 1
		w[i] = bxor(bxor(lshift(key[j], 24), lshift(key[j + 1], 16)), bxor(lshift(key[j + 2], 8), key[j + 3]))
	end

	-- Expand key
	for i = NK + 1, NB * (ROUNDS + 1) do
		local temp = w[i - 1]

		if (i - 1) % NK == 0 then
			-- RotWord + SubWord + Rcon
			temp = bxor(
				bxor(lshift(SBOX[band(rshift(temp, 16), 0xFF) + 1], 24), lshift(SBOX[band(rshift(temp, 8), 0xFF) + 1], 16)),
				bxor(lshift(SBOX[band(temp, 0xFF) + 1], 8), SBOX[band(rshift(temp, 24), 0xFF) + 1])
			)
			temp = bxor(temp, lshift(RCON[(i - 1) // NK], 24))
		elseif NK > 6 and (i - 1) % NK == 4 then
			-- SubWord only for AES-256
			temp = bxor(
				bxor(lshift(SBOX[band(rshift(temp, 24), 0xFF) + 1], 24), lshift(SBOX[band(rshift(temp, 16), 0xFF) + 1], 16)),
				bxor(lshift(SBOX[band(rshift(temp, 8), 0xFF) + 1], 8), SBOX[band(temp, 0xFF) + 1])
			)
		end

		w[i] = bxor(w[i - NK], temp)
	end

	-- Generate decryption round keys (apply InvMixColumns to rounds 1 through ROUNDS-1)
	local dw: { number } = table_create(60) :: ByteArray

	-- First round key (round 0) stays the same but goes to position ROUNDS
	for i = 1, 4 do dw[ROUNDS * 4 + i] = w[i] end

	-- Middle round keys get InvMixColumns applied and reversed
	for r = 1, ROUNDS - 1 do
		local srcRk = r * 4
		local dstRk = (ROUNDS - r) * 4
		for i = 1, 4 do dw[dstRk + i] = inv_mix_column(w[srcRk + i]) end
	end

	-- Last round key (round ROUNDS) stays the same but goes to position 0
	for i = 1, 4 do dw[i] = w[ROUNDS * 4 + i] end

	return { roundKeys = w, decRoundKeys = dw, rounds = ROUNDS }
end

-- 16 block encryption
local function encrypt_block(key: AESKey, input: ByteArray, inputOffset: number?, output: ByteArray?, outputOffset: number?): ByteArray
	local inOff = inputOffset or 1
	local outOff = outputOffset or 1
	local out = output or (table_create(16) :: ByteArray)
	local w = key.roundKeys

	-- Set initial state from input (column-major)
	local s0 = bxor(bxor(bxor(lshift(input[inOff], 24), lshift(input[inOff + 1], 16)), bxor(lshift(input[inOff + 2], 8), input[inOff + 3])), w[1])
	local s1 = bxor(bxor(bxor(lshift(input[inOff + 4], 24), lshift(input[inOff + 5], 16)), bxor(lshift(input[inOff + 6], 8), input[inOff + 7])), w[2])
	local s2 = bxor(bxor(bxor(lshift(input[inOff + 8], 24), lshift(input[inOff + 9], 16)), bxor(lshift(input[inOff + 10], 8), input[inOff + 11])), w[3])
	local s3 = bxor(bxor(bxor(lshift(input[inOff + 12], 24), lshift(input[inOff + 13], 16)), bxor(lshift(input[inOff + 14], 8), input[inOff + 15])), w[4])

	-- Rounds 1 to ROUNDS-1
	local t0, t1, t2, t3
	for r = 1, ROUNDS - 1 do
		local rk = r * 4
		t0 = bxor(bxor(bxor(TE0[band(rshift(s0, 24), 0xFF)], TE1[band(rshift(s1, 16), 0xFF)]), bxor(TE2[band(rshift(s2, 8), 0xFF)], TE3[band(s3, 0xFF)])), w[rk + 1])
		t1 = bxor(bxor(bxor(TE0[band(rshift(s1, 24), 0xFF)], TE1[band(rshift(s2, 16), 0xFF)]), bxor(TE2[band(rshift(s3, 8), 0xFF)], TE3[band(s0, 0xFF)])), w[rk + 2])
		t2 = bxor(bxor(bxor(TE0[band(rshift(s2, 24), 0xFF)], TE1[band(rshift(s3, 16), 0xFF)]), bxor(TE2[band(rshift(s0, 8), 0xFF)], TE3[band(s1, 0xFF)])), w[rk + 3])
		t3 = bxor(bxor(bxor(TE0[band(rshift(s3, 24), 0xFF)], TE1[band(rshift(s0, 16), 0xFF)]), bxor(TE2[band(rshift(s1, 8), 0xFF)], TE3[band(s2, 0xFF)])), w[rk + 4])
		s0, s1, s2, s3 = t0, t1, t2, t3
	end

	local rk = ROUNDS * 4
	t0 = bxor(bxor(bxor(lshift(SBOX[band(rshift(s0, 24), 0xFF) + 1], 24), lshift(SBOX[band(rshift(s1, 16), 0xFF) + 1], 16)), bxor(lshift(SBOX[band(rshift(s2, 8), 0xFF) + 1], 8), SBOX[band(s3, 0xFF) + 1])), w[rk + 1])
	t1 = bxor(bxor(bxor(lshift(SBOX[band(rshift(s1, 24), 0xFF) + 1], 24), lshift(SBOX[band(rshift(s2, 16), 0xFF) + 1], 16)), bxor(lshift(SBOX[band(rshift(s3, 8), 0xFF) + 1], 8), SBOX[band(s0, 0xFF) + 1])), w[rk + 2])
	t2 = bxor(bxor(bxor(lshift(SBOX[band(rshift(s2, 24), 0xFF) + 1], 24), lshift(SBOX[band(rshift(s3, 16), 0xFF) + 1], 16)), bxor(lshift(SBOX[band(rshift(s0, 8), 0xFF) + 1], 8), SBOX[band(s1, 0xFF) + 1])), w[rk + 3])
	t3 = bxor(bxor(bxor(lshift(SBOX[band(rshift(s3, 24), 0xFF) + 1], 24), lshift(SBOX[band(rshift(s0, 16), 0xFF) + 1], 16)), bxor(lshift(SBOX[band(rshift(s1, 8), 0xFF) + 1], 8), SBOX[band(s2, 0xFF) + 1])), w[rk + 4])

	out[outOff] = band(rshift(t0, 24), 0xFF); out[outOff + 1] = band(rshift(t0, 16), 0xFF); out[outOff + 2] = band(rshift(t0, 8), 0xFF); out[outOff + 3] = band(t0, 0xFF)
	out[outOff + 4] = band(rshift(t1, 24), 0xFF); out[outOff + 5] = band(rshift(t1, 16), 0xFF); out[outOff + 6] = band(rshift(t1, 8), 0xFF); out[outOff + 7] = band(t1, 0xFF)
	out[outOff + 8] = band(rshift(t2, 24), 0xFF); out[outOff + 9] = band(rshift(t2, 16), 0xFF); out[outOff + 10] = band(rshift(t2, 8), 0xFF); out[outOff + 11] = band(t2, 0xFF)
	out[outOff + 12] = band(rshift(t3, 24), 0xFF); out[outOff + 13] = band(rshift(t3, 16), 0xFF); out[outOff + 14] = band(rshift(t3, 8), 0xFF); out[outOff + 15] = band(t3, 0xFF)

	return out
end

local function decrypt_block(key: AESKey, input: ByteArray, inputOffset: number?, output: ByteArray?, outputOffset: number?): ByteArray
	local inOff = inputOffset or 1
	local outOff = outputOffset or 1
	local out = output or (table_create(16) :: ByteArray)
	local dw = key.decRoundKeys

	-- Initial state from input (XOR with first decryption round key)
	local s0 = bxor(bxor(bxor(lshift(input[inOff], 24), lshift(input[inOff + 1], 16)), bxor(lshift(input[inOff + 2], 8), input[inOff + 3])), dw[1])
	local s1 = bxor(bxor(bxor(lshift(input[inOff + 4], 24), lshift(input[inOff + 5], 16)), bxor(lshift(input[inOff + 6], 8), input[inOff + 7])), dw[2])
	local s2 = bxor(bxor(bxor(lshift(input[inOff + 8], 24), lshift(input[inOff + 9], 16)), bxor(lshift(input[inOff + 10], 8), input[inOff + 11])), dw[3])
	local s3 = bxor(bxor(bxor(lshift(input[inOff + 12], 24), lshift(input[inOff + 13], 16)), bxor(lshift(input[inOff + 14], 8), input[inOff + 15])), dw[4])

	local t0, t1, t2, t3
	for r = 1, ROUNDS - 1 do
		local rk = r * 4
		t0 = bxor(bxor(bxor(TD0[band(rshift(s0, 24), 0xFF)], TD1[band(rshift(s3, 16), 0xFF)]), bxor(TD2[band(rshift(s2, 8), 0xFF)], TD3[band(s1, 0xFF)])), dw[rk + 1])
		t1 = bxor(bxor(bxor(TD0[band(rshift(s1, 24), 0xFF)], TD1[band(rshift(s0, 16), 0xFF)]), bxor(TD2[band(rshift(s3, 8), 0xFF)], TD3[band(s2, 0xFF)])), dw[rk + 2])
		t2 = bxor(bxor(bxor(TD0[band(rshift(s2, 24), 0xFF)], TD1[band(rshift(s1, 16), 0xFF)]), bxor(TD2[band(rshift(s0, 8), 0xFF)], TD3[band(s3, 0xFF)])), dw[rk + 3])
		t3 = bxor(bxor(bxor(TD0[band(rshift(s3, 24), 0xFF)], TD1[band(rshift(s2, 16), 0xFF)]), bxor(TD2[band(rshift(s1, 8), 0xFF)], TD3[band(s0, 0xFF)])), dw[rk + 4])
		s0, s1, s2, s3 = t0, t1, t2, t3
	end

	local rk = ROUNDS * 4
	t0 = bxor(bxor(bxor(lshift(INV_SBOX[band(rshift(s0, 24), 0xFF) + 1], 24), lshift(INV_SBOX[band(rshift(s3, 16), 0xFF) + 1], 16)), bxor(lshift(INV_SBOX[band(rshift(s2, 8), 0xFF) + 1], 8), INV_SBOX[band(s1, 0xFF) + 1])), dw[rk + 1])
	t1 = bxor(bxor(bxor(lshift(INV_SBOX[band(rshift(s1, 24), 0xFF) + 1], 24), lshift(INV_SBOX[band(rshift(s0, 16), 0xFF) + 1], 16)), bxor(lshift(INV_SBOX[band(rshift(s3, 8), 0xFF) + 1], 8), INV_SBOX[band(s2, 0xFF) + 1])), dw[rk + 2])
	t2 = bxor(bxor(bxor(lshift(INV_SBOX[band(rshift(s2, 24), 0xFF) + 1], 24), lshift(INV_SBOX[band(rshift(s1, 16), 0xFF) + 1], 16)), bxor(lshift(INV_SBOX[band(rshift(s0, 8), 0xFF) + 1], 8), INV_SBOX[band(s3, 0xFF) + 1])), dw[rk + 3])
	t3 = bxor(bxor(bxor(lshift(INV_SBOX[band(rshift(s3, 24), 0xFF) + 1], 24), lshift(INV_SBOX[band(rshift(s2, 16), 0xFF) + 1], 16)), bxor(lshift(INV_SBOX[band(rshift(s1, 8), 0xFF) + 1], 8), INV_SBOX[band(s0, 0xFF) + 1])), dw[rk + 4])

	out[outOff] = band(rshift(t0, 24), 0xFF); out[outOff + 1] = band(rshift(t0, 16), 0xFF); out[outOff + 2] = band(rshift(t0, 8), 0xFF); out[outOff + 3] = band(t0, 0xFF)
	out[outOff + 4] = band(rshift(t1, 24), 0xFF); out[outOff + 5] = band(rshift(t1, 16), 0xFF); out[outOff + 6] = band(rshift(t1, 8), 0xFF); out[outOff + 7] = band(t1, 0xFF)
	out[outOff + 8] = band(rshift(t2, 24), 0xFF); out[outOff + 9] = band(rshift(t2, 16), 0xFF); out[outOff + 10] = band(rshift(t2, 8), 0xFF); out[outOff + 11] = band(t2, 0xFF)
	out[outOff + 12] = band(rshift(t3, 24), 0xFF); out[outOff + 13] = band(rshift(t3, 16), 0xFF); out[outOff + 14] = band(rshift(t3, 8), 0xFF); out[outOff + 15] = band(t3, 0xFF)

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
