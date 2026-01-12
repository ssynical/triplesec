--!native
--!strict
--!optimize 2

local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
local lshift, rshift = bit32.lshift, bit32.rshift
local lrotate, rrotate = bit32.lrotate, bit32.rrotate
local table_create = table.create

export type ByteArray = { number }
export type SerpentKey = { subkeys: { { number } } }

local BLOCK_SIZE: number = 16
local KEY_SIZE: number = 32
local ROUNDS: number = 32
local PHI: number = 0x9E3779B9

-- Initial Permutation for NESSIE compliance (https://www.cl.cam.ac.uk/archive/rja14/Papers/serpent.pdf)
-- This fucntion converts from standard representation to bitslice representation
local function initial_permutation(x0: number, x1: number, x2: number, x3: number): (number, number, number, number)
	local y0, y1, y2, y3 = 0, 0, 0, 0
	for i = 0, 31 do
		local bit0 = band(rshift(x0, i), 1)
		local bit1 = band(rshift(x1, i), 1)
		local bit2 = band(rshift(x2, i), 1)
		local bit3 = band(rshift(x3, i), 1)
		y0 = bor(y0, lshift(bit0, i))
		y1 = bor(y1, lshift(bit1, i))
		y2 = bor(y2, lshift(bit2, i))
		y3 = bor(y3, lshift(bit3, i))
	end
	-- Interleave bits, bit i*4+j of input word j goes to bit i of output word j
	local r0, r1, r2, r3 = 0, 0, 0, 0
	for i = 0, 31 do
		local srcWord = i % 4
		local srcBit = (i // 4) + (i % 4) * 8
		local bit
		if srcWord == 0 then bit = band(rshift(x0, srcBit % 32), 1)
		elseif srcWord == 1 then bit = band(rshift(x1, srcBit % 32), 1)
		elseif srcWord == 2 then bit = band(rshift(x2, srcBit % 32), 1)
		else bit = band(rshift(x3, srcBit % 32), 1) end
		r0 = bor(r0, lshift(bit, i))
	end
	for i = 0, 31 do
		local srcWord = (i + 1) % 4
		local srcBit = (i // 4) + ((i + 1) % 4) * 8
		local bit
		if srcWord == 0 then bit = band(rshift(x0, srcBit % 32), 1)
		elseif srcWord == 1 then bit = band(rshift(x1, srcBit % 32), 1)
		elseif srcWord == 2 then bit = band(rshift(x2, srcBit % 32), 1)
		else bit = band(rshift(x3, srcBit % 32), 1) end
		r1 = bor(r1, lshift(bit, i))
	end
	for i = 0, 31 do
		local srcWord = (i + 2) % 4
		local srcBit = (i // 4) + ((i + 2) % 4) * 8
		local bit
		if srcWord == 0 then bit = band(rshift(x0, srcBit % 32), 1)
		elseif srcWord == 1 then bit = band(rshift(x1, srcBit % 32), 1)
		elseif srcWord == 2 then bit = band(rshift(x2, srcBit % 32), 1)
		else bit = band(rshift(x3, srcBit % 32), 1) end
		r2 = bor(r2, lshift(bit, i))
	end
	for i = 0, 31 do
		local srcWord = (i + 3) % 4
		local srcBit = (i // 4) + ((i + 3) % 4) * 8
		local bit
		if srcWord == 0 then bit = band(rshift(x0, srcBit % 32), 1)
		elseif srcWord == 1 then bit = band(rshift(x1, srcBit % 32), 1)
		elseif srcWord == 2 then bit = band(rshift(x2, srcBit % 32), 1)
		else bit = band(rshift(x3, srcBit % 32), 1) end
		r3 = bor(r3, lshift(bit, i))
	end
	return r0, r1, r2, r3
end

-- Final Permutation
-- This function converts from bitslice representation to standard representation (inverse of prev.)
local function final_permutation(x0: number, x1: number, x2: number, x3: number): (number, number, number, number)
	local r0, r1, r2, r3 = 0, 0, 0, 0
	for i = 0, 31 do
		local dstBit = (i % 4) * 8 + (i // 4)
		local bit = band(rshift(x0, i), 1)
		local dstWord = i % 4
		if dstWord == 0 then r0 = bor(r0, lshift(bit, dstBit % 32))
		elseif dstWord == 1 then r1 = bor(r1, lshift(bit, dstBit % 32))
		elseif dstWord == 2 then r2 = bor(r2, lshift(bit, dstBit % 32))
		else r3 = bor(r3, lshift(bit, dstBit % 32)) end
	end
	for i = 0, 31 do
		local dstBit = ((i + 3) % 4) * 8 + (i // 4)
		local bit = band(rshift(x1, i), 1)
		local dstWord = (i + 3) % 4
		if dstWord == 0 then r0 = bor(r0, lshift(bit, dstBit % 32))
		elseif dstWord == 1 then r1 = bor(r1, lshift(bit, dstBit % 32))
		elseif dstWord == 2 then r2 = bor(r2, lshift(bit, dstBit % 32))
		else r3 = bor(r3, lshift(bit, dstBit % 32)) end
	end
	for i = 0, 31 do
		local dstBit = ((i + 2) % 4) * 8 + (i // 4)
		local bit = band(rshift(x2, i), 1)
		local dstWord = (i + 2) % 4
		if dstWord == 0 then r0 = bor(r0, lshift(bit, dstBit % 32))
		elseif dstWord == 1 then r1 = bor(r1, lshift(bit, dstBit % 32))
		elseif dstWord == 2 then r2 = bor(r2, lshift(bit, dstBit % 32))
		else r3 = bor(r3, lshift(bit, dstBit % 32)) end
	end
	for i = 0, 31 do
		local dstBit = ((i + 1) % 4) * 8 + (i // 4)
		local bit = band(rshift(x3, i), 1)
		local dstWord = (i + 1) % 4
		if dstWord == 0 then r0 = bor(r0, lshift(bit, dstBit % 32))
		elseif dstWord == 1 then r1 = bor(r1, lshift(bit, dstBit % 32))
		elseif dstWord == 2 then r2 = bor(r2, lshift(bit, dstBit % 32))
		else r3 = bor(r3, lshift(bit, dstBit % 32)) end
	end
	return r0, r1, r2, r3
end

local function SBOX0(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bxor(b, c)
	local t02 = bor(a, d)
	local t03 = bxor(a, b)
	local z = bxor(t02, t01)
	local t05 = bor(c, z)
	local t06 = bxor(a, d)
	local t07 = bor(b, c)
	local t08 = band(d, t05)
	local t09 = band(t03, t07)
	local y = bxor(t09, t08)
	local t11 = band(t09, y)
	local t12 = bxor(c, d)
	local t13 = bxor(t07, t11)
	local t14 = band(b, t06)
	local t15 = bxor(t06, t13)
	local w = bnot(t15)
	local t17 = bxor(w, t14)
	local x = bxor(t12, t17)
	return w, x, y, z
end

local function SBOX0_INVERSE(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bxor(c, d)
	local t02 = bor(a, b)
	local t03 = bor(b, c)
	local t04 = band(c, t01)
	local t05 = bxor(t02, t01)
	local t06 = bor(a, t04)
	local y = bnot(t05)
	local t08 = bxor(b, d)
	local t09 = band(t03, t08)
	local t10 = bor(d, y)
	local x = bxor(t09, t06)
	local t12 = bor(a, t05)
	local t13 = bxor(x, t12)
	local t14 = bxor(t03, t10)
	local t15 = bxor(a, c)
	local z = bxor(t14, t13)
	local t17 = band(t05, t13)
	local t18 = bor(t14, t17)
	local w = bxor(t15, t18)
	return w, x, y, z
end

local function SBOX1(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bor(a, d)
	local t02 = bxor(c, d)
	local t03 = bnot(b)
	local t04 = bxor(a, c)
	local t05 = bor(a, t03)
	local t06 = band(d, t04)
	local t07 = band(t01, t02)
	local t08 = bor(b, t06)
	local y = bxor(t02, t05)
	local t10 = bxor(t07, t08)
	local t11 = bxor(t01, t10)
	local t12 = bxor(y, t11)
	local t13 = band(b, d)
	local z = bnot(t10)
	local x = bxor(t13, t12)
	local t16 = bor(t10, x)
	local t17 = band(t05, t16)
	local w = bxor(c, t17)
	return w, x, y, z
end

local function SBOX1_INVERSE(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bxor(a, b)
	local t02 = bor(b, d)
	local t03 = band(a, c)
	local t04 = bxor(c, t02)
	local t05 = bor(a, t04)
	local t06 = band(t01, t05)
	local t07 = bor(d, t03)
	local t08 = bxor(b, t06)
	local t09 = bxor(t07, t06)
	local t10 = bor(t04, t03)
	local t11 = band(d, t08)
	local y = bnot(t09)
	local x = bxor(t10, t11)
	local t14 = bor(a, y)
	local t15 = bxor(t06, x)
	local z = bxor(t01, t04)
	local t17 = bxor(c, t15)
	local w = bxor(t14, t17)
	return w, x, y, z
end

local function SBOX2(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bor(a, c)
	local t02 = bxor(a, b)
	local t03 = bxor(d, t01)
	local w = bxor(t02, t03)
	local t05 = bxor(c, w)
	local t06 = bxor(b, t05)
	local t07 = bor(b, t05)
	local t08 = band(t01, t06)
	local t09 = bxor(t03, t07)
	local t10 = bor(t02, t09)
	local x = bxor(t10, t08)
	local t12 = bor(a, d)
	local t13 = bxor(t09, x)
	local t14 = bxor(b, t13)
	local z = bnot(t09)
	local y = bxor(t12, t14)
	return w, x, y, z
end

local function SBOX2_INVERSE(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bxor(a, d)
	local t02 = bxor(c, d)
	local t03 = band(a, c)
	local t04 = bor(b, t02)
	local w = bxor(t01, t04)
	local t06 = bor(a, c)
	local t07 = bor(d, w)
	local t08 = bnot(d)
	local t09 = band(b, t06)
	local t10 = bor(t08, t03)
	local t11 = band(b, t07)
	local t12 = band(t06, t02)
	local z = bxor(t09, t10)
	local x = bxor(t12, t11)
	local t15 = band(c, z)
	local t16 = bxor(w, x)
	local t17 = bxor(t10, t15)
	local y = bxor(t16, t17)
	return w, x, y, z
end

local function SBOX3(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bxor(a, c)
	local t02 = bor(a, d)
	local t03 = band(a, d)
	local t04 = band(t01, t02)
	local t05 = bor(b, t03)
	local t06 = band(a, b)
	local t07 = bxor(d, t04)
	local t08 = bor(c, t06)
	local t09 = bxor(b, t07)
	local t10 = band(d, t05)
	local t11 = bxor(t02, t10)
	local z = bxor(t08, t09)
	local t13 = bor(d, z)
	local t14 = bor(a, t07)
	local t15 = band(b, t13)
	local y = bxor(t08, t11)
	local w = bxor(t14, t15)
	local x = bxor(t05, t04)
	return w, x, y, z
end

local function SBOX3_INVERSE(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bor(c, d)
	local t02 = bor(a, d)
	local t03 = bxor(c, t02)
	local t04 = bxor(b, t02)
	local t05 = bxor(a, d)
	local t06 = band(t04, t03)
	local t07 = band(b, t01)
	local y = bxor(t05, t06)
	local t09 = bxor(a, t03)
	local w = bxor(t07, t03)
	local t11 = bor(w, t05)
	local t12 = band(t09, t11)
	local t13 = band(a, y)
	local t14 = bxor(t01, t05)
	local x = bxor(b, t12)
	local t16 = bor(b, t13)
	local z = bxor(t14, t16)
	return w, x, y, z
end

local function SBOX4(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bor(a, b)
	local t02 = bor(b, c)
	local t03 = bxor(a, t02)
	local t04 = bxor(b, d)
	local t05 = bor(d, t03)
	local t06 = band(d, t01)
	local z = bxor(t03, t06)
	local t08 = band(z, t04)
	local t09 = band(t04, t05)
	local t10 = bxor(c, t06)
	local t11 = band(b, c)
	local t12 = bxor(t04, t08)
	local t13 = bor(t11, t03)
	local t14 = bxor(t10, t09)
	local t15 = band(a, t05)
	local t16 = bor(t11, t12)
	local y = bxor(t13, t08)
	local x = bxor(t15, t16)
	local w = bnot(t14)
	return w, x, y, z
end

local function SBOX4_INVERSE(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bor(b, d)
	local t02 = bor(c, d)
	local t03 = band(a, t01)
	local t04 = bxor(b, t02)
	local t05 = bxor(c, d)
	local t06 = bnot(t03)
	local t07 = band(a, t04)
	local x = bxor(t05, t07)
	local t09 = bor(x, t06)
	local t10 = bxor(a, t07)
	local t11 = bxor(t01, t09)
	local t12 = bxor(d, t04)
	local t13 = bor(c, t10)
	local z = bxor(t03, t12)
	local t15 = bxor(a, t04)
	local y = bxor(t11, t13)
	local w = bxor(t15, t09)
	return w, x, y, z
end

local function SBOX5(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bxor(b, d)
	local t02 = bor(b, d)
	local t03 = band(a, t01)
	local t04 = bxor(c, t02)
	local t05 = bxor(t03, t04)
	local w = bnot(t05)
	local t07 = bxor(a, t01)
	local t08 = bor(d, w)
	local t09 = bor(b, t05)
	local t10 = bxor(d, t08)
	local t11 = bor(b, t07)
	local t12 = bor(t03, w)
	local t13 = bor(t07, t10)
	local t14 = bxor(t01, t11)
	local y = bxor(t09, t13)
	local x = bxor(t07, t08)
	local z = bxor(t12, t14)
	return w, x, y, z
end

local function SBOX5_INVERSE(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = band(a, d)
	local t02 = bxor(c, t01)
	local t03 = bxor(a, d)
	local t04 = band(b, t02)
	local t05 = band(a, c)
	local w = bxor(t03, t04)
	local t07 = band(a, w)
	local t08 = bxor(t01, w)
	local t09 = bor(b, t05)
	local t10 = bnot(b)
	local x = bxor(t08, t09)
	local t12 = bor(t10, t07)
	local t13 = bor(w, x)
	local z = bxor(t02, t12)
	local t15 = bxor(t02, t13)
	local t16 = bxor(b, d)
	local y = bxor(t16, t15)
	return w, x, y, z
end

local function SBOX6(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = band(a, d)
	local t02 = bxor(b, c)
	local t03 = bxor(a, d)
	local t04 = bxor(t01, t02)
	local t05 = bor(b, c)
	local x = bnot(t04)
	local t07 = band(t03, t05)
	local t08 = band(b, x)
	local t09 = bor(a, c)
	local t10 = bxor(t07, t08)
	local t11 = bor(b, d)
	local t12 = bxor(c, t11)
	local t13 = bxor(t09, t10)
	local y = bnot(t13)
	local t15 = band(x, t03)
	local z = bxor(t12, t07)
	local t17 = bxor(a, b)
	local t18 = bxor(y, t15)
	local w = bxor(t17, t18)
	return w, x, y, z
end

local function SBOX6_INVERSE(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = bxor(a, c)
	local t02 = bnot(c)
	local t03 = band(b, t01)
	local t04 = bor(b, t02)
	local t05 = bor(d, t03)
	local t06 = bxor(b, d)
	local t07 = band(a, t04)
	local t08 = bor(a, t02)
	local t09 = bxor(t07, t05)
	local x = bxor(t06, t08)
	local w = bnot(t09)
	local t12 = band(b, w)
	local t13 = band(t01, t05)
	local t14 = bxor(t01, t12)
	local t15 = bxor(t07, t13)
	local t16 = bor(d, t02)
	local t17 = bxor(a, x)
	local z = bxor(t17, t15)
	local y = bxor(t16, t14)
	return w, x, y, z
end

local function SBOX7(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = band(a, c)
	local t02 = bnot(d)
	local t03 = band(a, t02)
	local t04 = bor(b, t01)
	local t05 = band(a, b)
	local t06 = bxor(c, t04)
	local z = bxor(t03, t06)
	local t08 = bor(c, z)
	local t09 = bor(d, t05)
	local t10 = bxor(a, t08)
	local t11 = band(t04, z)
	local x = bxor(t09, t10)
	local t13 = bxor(b, x)
	local t14 = bxor(t01, x)
	local t15 = bxor(c, t05)
	local t16 = bor(t11, t13)
	local t17 = bor(t02, t14)
	local w = bxor(t15, t17)
	local y = bxor(a, t16)
	return w, x, y, z
end

local function SBOX7_INVERSE(a: number, b: number, c: number, d: number): (number, number, number, number)
	local t01 = band(a, b)
	local t02 = bor(a, b)
	local t03 = bor(c, t01)
	local t04 = band(d, t02)
	local z = bxor(t03, t04)
	local t06 = bxor(b, t04)
	local t07 = bxor(d, z)
	local t08 = bnot(t07)
	local t09 = bor(t06, t08)
	local t10 = bxor(b, d)
	local t11 = bor(a, d)
	local x = bxor(a, t09)
	local t13 = bxor(c, t06)
	local t14 = band(c, t11)
	local t15 = bor(d, x)
	local t16 = bor(t01, t10)
	local w = bxor(t13, t15)
	local y = bxor(t14, t16)
	return w, x, y, z
end

local function LT(x0: number, x1: number, x2: number, x3: number): (number, number, number, number)
	x0 = lrotate(x0, 13); x2 = lrotate(x2, 3)
	x1 = bxor(bxor(x1, x0), x2); x3 = bxor(bxor(x3, x2), lshift(x0, 3))
	x1 = lrotate(x1, 1); x3 = lrotate(x3, 7)
	x0 = bxor(bxor(x0, x1), x3); x2 = bxor(bxor(x2, x3), lshift(x1, 7))
	x0 = lrotate(x0, 5); x2 = lrotate(x2, 22)
	return x0, x1, x2, x3
end

local function ILT(x0: number, x1: number, x2: number, x3: number): (number, number, number, number)
	x2 = rrotate(x2, 22); x0 = rrotate(x0, 5)
	x2 = bxor(bxor(x2, x3), lshift(x1, 7)); x0 = bxor(bxor(x0, x1), x3)
	x3 = rrotate(x3, 7); x1 = rrotate(x1, 1)
	x3 = bxor(bxor(x3, x2), lshift(x0, 3)); x1 = bxor(bxor(x1, x0), x2)
	x2 = rrotate(x2, 3); x0 = rrotate(x0, 13)
	return x0, x1, x2, x3
end

local function expand_key(key: ByteArray): SerpentKey
	local keyLen = #key
	if keyLen < KEY_SIZE then error(`Serpent requires {KEY_SIZE}-byte key, got {keyLen} bytes`) end

	local w: { number } = table_create(140) :: { number }

	for i = 1, 8 do
		local j = (i - 1) * 4 + 1
		w[i] = bor(bor(key[j], lshift(key[j + 1], 8)), bor(lshift(key[j + 2], 16), lshift(key[j + 3], 24)))
	end

	for i = 9, 140 do
		local t = bxor(bxor(bxor(w[i - 8], w[i - 5]), bxor(w[i - 3], w[i - 1])), bxor(PHI, i - 9))
		w[i] = lrotate(t, 11)
	end

	local subkeys: { { number } } = table_create(33) :: { { number } }
	for i = 0, 32 do
		local j = i * 4 + 9
		local r0, r1, r2, r3 = w[j], w[j + 1], w[j + 2], w[j + 3]
		local sbox = (3 - i) % 8
		if sbox < 0 then sbox = sbox + 8 end

		if sbox == 0 then r0, r1, r2, r3 = SBOX0(r0, r1, r2, r3)
		elseif sbox == 1 then r0, r1, r2, r3 = SBOX1(r0, r1, r2, r3)
		elseif sbox == 2 then r0, r1, r2, r3 = SBOX2(r0, r1, r2, r3)
		elseif sbox == 3 then r0, r1, r2, r3 = SBOX3(r0, r1, r2, r3)
		elseif sbox == 4 then r0, r1, r2, r3 = SBOX4(r0, r1, r2, r3)
		elseif sbox == 5 then r0, r1, r2, r3 = SBOX5(r0, r1, r2, r3)
		elseif sbox == 6 then r0, r1, r2, r3 = SBOX6(r0, r1, r2, r3)
		else r0, r1, r2, r3 = SBOX7(r0, r1, r2, r3) end

		subkeys[i + 1] = { r0, r1, r2, r3 }
	end

	return { subkeys = subkeys }
end

local function encrypt_block(key: SerpentKey, input: ByteArray, inputOffset: number?, output: ByteArray?, outputOffset: number?): ByteArray
	local inOff = inputOffset or 1
	local outOff = outputOffset or 1
	local out = output or table_create(16) :: ByteArray
	local sk = key.subkeys

	local x0: number = bor(bor(input[inOff], lshift(input[inOff + 1], 8)), bor(lshift(input[inOff + 2], 16), lshift(input[inOff + 3], 24)))
	local x1: number = bor(bor(input[inOff + 4], lshift(input[inOff + 5], 8)), bor(lshift(input[inOff + 6], 16), lshift(input[inOff + 7], 24)))
	local x2: number = bor(bor(input[inOff + 8], lshift(input[inOff + 9], 8)), bor(lshift(input[inOff + 10], 16), lshift(input[inOff + 11], 24)))
	local x3: number = bor(bor(input[inOff + 12], lshift(input[inOff + 13], 8)), bor(lshift(input[inOff + 14], 16), lshift(input[inOff + 15], 24)))

	for r = 1, 32 do
		local k = sk[r]
		x0, x1, x2, x3 = bxor(x0, k[1]), bxor(x1, k[2]), bxor(x2, k[3]), bxor(x3, k[4])
		assert(x3 ~= nil, "x3 cannot be nil")
		local sbox = (r - 1) % 8
		if sbox == 0 then x0, x1, x2, x3 = SBOX0(x0, x1, x2, x3)
		elseif sbox == 1 then x0, x1, x2, x3 = SBOX1(x0, x1, x2, x3)
		elseif sbox == 2 then x0, x1, x2, x3 = SBOX2(x0, x1, x2, x3)
		elseif sbox == 3 then x0, x1, x2, x3 = SBOX3(x0, x1, x2, x3)
		elseif sbox == 4 then x0, x1, x2, x3 = SBOX4(x0, x1, x2, x3)
		elseif sbox == 5 then x0, x1, x2, x3 = SBOX5(x0, x1, x2, x3)
		elseif sbox == 6 then x0, x1, x2, x3 = SBOX6(x0, x1, x2, x3)
		else x0, x1, x2, x3 = SBOX7(x0, x1, x2, x3) end

		if r < 32 then x0, x1, x2, x3 = LT(x0, x1, x2, x3) end
	end

	local k = sk[33]
	x0, x1, x2, x3 = bxor(x0, k[1]), bxor(x1, k[2]), bxor(x2, k[3]), bxor(x3, k[4])

	out[outOff] = band(x0, 0xFF); out[outOff + 1] = band(rshift(x0, 8), 0xFF); out[outOff + 2] = band(rshift(x0, 16), 0xFF); out[outOff + 3] = band(rshift(x0, 24), 0xFF)
	out[outOff + 4] = band(x1, 0xFF); out[outOff + 5] = band(rshift(x1, 8), 0xFF); out[outOff + 6] = band(rshift(x1, 16), 0xFF); out[outOff + 7] = band(rshift(x1, 24), 0xFF)
	out[outOff + 8] = band(x2, 0xFF); out[outOff + 9] = band(rshift(x2, 8), 0xFF); out[outOff + 10] = band(rshift(x2, 16), 0xFF); out[outOff + 11] = band(rshift(x2, 24), 0xFF)
	out[outOff + 12] = band(x3, 0xFF); out[outOff + 13] = band(rshift(x3, 8), 0xFF); out[outOff + 14] = band(rshift(x3, 16), 0xFF); out[outOff + 15] = band(rshift(x3, 24), 0xFF)

	return out
end

local function decrypt_block(key: SerpentKey, input: ByteArray, inputOffset: number?, output: ByteArray?, outputOffset: number?): ByteArray
	local inOff = inputOffset or 1
	local outOff = outputOffset or 1
	local out = output or table_create(16) :: ByteArray
	local sk = key.subkeys

	local x0: number = bor(bor(input[inOff], lshift(input[inOff + 1], 8)), bor(lshift(input[inOff + 2], 16), lshift(input[inOff + 3], 24)))
	local x1: number = bor(bor(input[inOff + 4], lshift(input[inOff + 5], 8)), bor(lshift(input[inOff + 6], 16), lshift(input[inOff + 7], 24)))
	local x2: number = bor(bor(input[inOff + 8], lshift(input[inOff + 9], 8)), bor(lshift(input[inOff + 10], 16), lshift(input[inOff + 11], 24)))
	local x3: number = bor(bor(input[inOff + 12], lshift(input[inOff + 13], 8)), bor(lshift(input[inOff + 14], 16), lshift(input[inOff + 15], 24)))

	local k = sk[33]
	x0, x1, x2, x3 = bxor(x0, k[1]), bxor(x1, k[2]), bxor(x2, k[3]), bxor(x3, k[4])
	assert(x3 ~= nil, "x3 cannot be nil")
	x0, x1, x2, x3 = SBOX7_INVERSE(x0, x1, x2, x3)
	k = sk[32]
	x0, x1, x2, x3 = bxor(x0, k[1]), bxor(x1, k[2]), bxor(x2, k[3]), bxor(x3, k[4])

	for r = 31, 1, -1 do
		assert(x3 ~= nil, "x3 cannot be nil")
		x0, x1, x2, x3 = ILT(x0, x1, x2, x3)

		local sbox = (r - 1) % 8
		if sbox == 0 then x0, x1, x2, x3 = SBOX0_INVERSE(x0, x1, x2, x3)
		elseif sbox == 1 then x0, x1, x2, x3 = SBOX1_INVERSE(x0, x1, x2, x3)
		elseif sbox == 2 then x0, x1, x2, x3 = SBOX2_INVERSE(x0, x1, x2, x3)
		elseif sbox == 3 then x0, x1, x2, x3 = SBOX3_INVERSE(x0, x1, x2, x3)
		elseif sbox == 4 then x0, x1, x2, x3 = SBOX4_INVERSE(x0, x1, x2, x3)
		elseif sbox == 5 then x0, x1, x2, x3 = SBOX5_INVERSE(x0, x1, x2, x3)
		elseif sbox == 6 then x0, x1, x2, x3 = SBOX6_INVERSE(x0, x1, x2, x3)
		else x0, x1, x2, x3 = SBOX7_INVERSE(x0, x1, x2, x3) end

		k = sk[r]
		x0, x1, x2, x3 = bxor(x0, k[1]), bxor(x1, k[2]), bxor(x2, k[3]), bxor(x3, k[4])
	end

	out[outOff] = band(x0, 0xFF); out[outOff + 1] = band(rshift(x0, 8), 0xFF); out[outOff + 2] = band(rshift(x0, 16), 0xFF); out[outOff + 3] = band(rshift(x0, 24), 0xFF)
	out[outOff + 4] = band(x1, 0xFF); out[outOff + 5] = band(rshift(x1, 8), 0xFF); out[outOff + 6] = band(rshift(x1, 16), 0xFF); out[outOff + 7] = band(rshift(x1, 24), 0xFF)
	out[outOff + 8] = band(x2, 0xFF); out[outOff + 9] = band(rshift(x2, 8), 0xFF); out[outOff + 10] = band(rshift(x2, 16), 0xFF); out[outOff + 11] = band(rshift(x2, 24), 0xFF)
	out[outOff + 12] = band(x3, 0xFF); out[outOff + 13] = band(rshift(x3, 8), 0xFF); out[outOff + 14] = band(rshift(x3, 16), 0xFF); out[outOff + 15] = band(rshift(x3, 24), 0xFF)

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