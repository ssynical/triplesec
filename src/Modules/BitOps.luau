--!native
--!strict
--!optimize 2

local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
local lshift, rshift = bit32.lshift, bit32.rshift
local lrotate, rrotate = bit32.lrotate, bit32.rrotate
local extract, replace = bit32.extract, bit32.replace

export type Word32 = number
export type Word64 = { hi: number, lo: number }
export type ByteArray = { number }

local WORD32_MAX: number = 0xFFFFFFFF

local function and32(a: number, b: number): number return band(a, b) end
local function or32(a: number, b: number): number return bor(a, b) end
local function xor32(a: number, b: number): number return bxor(a, b) end
local function not32(a: number): number return band(bnot(a), WORD32_MAX) end
local function shl32(a: number, n: number): number return lshift(a, n) end
local function shr32(a: number, n: number): number return rshift(a, n) end
local function rol32(a: number, n: number): number return lrotate(a, n) end
local function ror32(a: number, n: number): number return rrotate(a, n) end

local function xor32_3(a: number, b: number, c: number): number return bxor(bxor(a, b), c) end
local function xor32_4(a: number, b: number, c: number, d: number): number return bxor(bxor(a, b), bxor(c, d)) end
local function xor32_5(a: number, b: number, c: number, d: number, e: number): number return bxor(bxor(bxor(a, b), bxor(c, d)), e) end

local function word64(hi: number, lo: number): Word64 return { hi = band(hi, WORD32_MAX), lo = band(lo, WORD32_MAX) } end

local function word64_from_bytes(b1: number, b2: number, b3: number, b4: number, b5: number, b6: number, b7: number, b8: number): Word64
	return { hi = bor(bor(lshift(b1, 24), lshift(b2, 16)), bor(lshift(b3, 8), b4)), lo = bor(bor(lshift(b5, 24), lshift(b6, 16)), bor(lshift(b7, 8), b8)) }
end

local function word64_to_bytes(w: Word64): (number, number, number, number, number, number, number, number)
	local hi, lo = w.hi, w.lo
	return extract(hi, 24, 8), extract(hi, 16, 8), extract(hi, 8, 8), extract(hi, 0, 8), extract(lo, 24, 8), extract(lo, 16, 8), extract(lo, 8, 8), extract(lo, 0, 8)
end

local function and64(a: Word64, b: Word64): Word64 return { hi = band(a.hi, b.hi), lo = band(a.lo, b.lo) } end
local function or64(a: Word64, b: Word64): Word64 return { hi = bor(a.hi, b.hi), lo = bor(a.lo, b.lo) } end
local function xor64(a: Word64, b: Word64): Word64 return { hi = bxor(a.hi, b.hi), lo = bxor(a.lo, b.lo) } end
local function not64(a: Word64): Word64 return { hi = band(bnot(a.hi), WORD32_MAX), lo = band(bnot(a.lo), WORD32_MAX) } end

local function xor64_3(a: Word64, b: Word64, c: Word64): Word64
	return { hi = bxor(bxor(a.hi, b.hi), c.hi), lo = bxor(bxor(a.lo, b.lo), c.lo) }
end

local function xor64_5(a: Word64, b: Word64, c: Word64, d: Word64, e: Word64): Word64
	return { hi = bxor(bxor(bxor(a.hi, b.hi), bxor(c.hi, d.hi)), e.hi), lo = bxor(bxor(bxor(a.lo, b.lo), bxor(c.lo, d.lo)), e.lo) }
end

local function add64(a: Word64, b: Word64): Word64
	local lo = a.lo + b.lo
	local carry = if lo > WORD32_MAX then 1 else 0
	return { hi = band(a.hi + b.hi + carry, WORD32_MAX), lo = band(lo, WORD32_MAX) }
end

local function add64_3(a: Word64, b: Word64, c: Word64): Word64 return add64(add64(a, b), c) end
local function add64_4(a: Word64, b: Word64, c: Word64, d: Word64): Word64 return add64(add64(a, b), add64(c, d)) end
local function add64_5(a: Word64, b: Word64, c: Word64, d: Word64, e: Word64): Word64 return add64(add64_4(a, b, c, d), e) end

local function shl64(a: Word64, n: number): Word64
	if n >= 64 then return { hi = 0, lo = 0 }
	elseif n >= 32 then return { hi = lshift(a.lo, n - 32), lo = 0 }
	elseif n == 0 then return { hi = a.hi, lo = a.lo }
	else return { hi = bor(lshift(a.hi, n), rshift(a.lo, 32 - n)), lo = lshift(a.lo, n) } end
end

local function shr64(a: Word64, n: number): Word64
	if n >= 64 then return { hi = 0, lo = 0 }
	elseif n >= 32 then return { hi = 0, lo = rshift(a.hi, n - 32) }
	elseif n == 0 then return { hi = a.hi, lo = a.lo }
	else return { hi = rshift(a.hi, n), lo = bor(rshift(a.lo, n), lshift(a.hi, 32 - n)) } end
end

local function rol64(a: Word64, n: number): Word64
	n = n % 64
	if n == 0 then return { hi = a.hi, lo = a.lo }
	elseif n == 32 then return { hi = a.lo, lo = a.hi }
	elseif n < 32 then return { hi = bor(lshift(a.hi, n), rshift(a.lo, 32 - n)), lo = bor(lshift(a.lo, n), rshift(a.hi, 32 - n)) }
	else n = n - 32; return { hi = bor(lshift(a.lo, n), rshift(a.hi, 32 - n)), lo = bor(lshift(a.hi, n), rshift(a.lo, 32 - n)) } end
end

local function ror64(a: Word64, n: number): Word64 return rol64(a, 64 - n) end

-- Big endian
local function bytes_to_word32_be(b1: number, b2: number, b3: number, b4: number): number
	return bor(bor(lshift(b1, 24), lshift(b2, 16)), bor(lshift(b3, 8), b4))
end

local function word32_to_bytes_be(w: number): (number, number, number, number)
	return extract(w, 24, 8), extract(w, 16, 8), extract(w, 8, 8), extract(w, 0, 8)
end

-- Little endian
local function bytes_to_word32_le(b1: number, b2: number, b3: number, b4: number): number
	return bor(bor(b1, lshift(b2, 8)), bor(lshift(b3, 16), lshift(b4, 24)))
end

local function word32_to_bytes_le(w: number): (number, number, number, number)
	return extract(w, 0, 8), extract(w, 8, 8), extract(w, 16, 8), extract(w, 24, 8)
end

local function bytes_to_words32_be(bytes: ByteArray, offset: number?, count: number?): { number }
	local start = offset or 1
	local n = count or ((#bytes - start + 1) // 4)
	local words = table.create(n) :: ByteArray
	for i = 1, n do
		local j = start + (i - 1) * 4
		words[i] = bor(bor(lshift(bytes[j], 24), lshift(bytes[j + 1], 16)), bor(lshift(bytes[j + 2], 8), bytes[j + 3]))
	end
	return words
end

local function words32_to_bytes_be(words: { number }): ByteArray
	local bytes = table.create(#words * 4) :: ByteArray
	for i = 1, #words do
		local w, j = words[i], (i - 1) * 4
		bytes[j + 1], bytes[j + 2], bytes[j + 3], bytes[j + 4] = extract(w, 24, 8), extract(w, 16, 8), extract(w, 8, 8), extract(w, 0, 8)
	end
	return bytes
end

local function bytes_to_words32_le(bytes: ByteArray, offset: number?, count: number?): { number }
	local start = offset or 1
	local n = count or ((#bytes - start + 1) // 4)
	local words = table.create(n) :: { number }
	for i = 1, n do
		local j = start + (i - 1) * 4
		words[i] = bor(bor(bytes[j], lshift(bytes[j + 1], 8)), bor(lshift(bytes[j + 2], 16), lshift(bytes[j + 3], 24)))
	end
	return words
end

local function words32_to_bytes_le(words: { number }): ByteArray
	local bytes = table.create(#words * 4) :: ByteArray
	for i = 1, #words do
		local w, j = words[i], (i - 1) * 4
		bytes[j + 1], bytes[j + 2], bytes[j + 3], bytes[j + 4] = extract(w, 0, 8), extract(w, 8, 8), extract(w, 16, 8), extract(w, 24, 8)
	end
	return bytes
end

local function bytes_to_words64_be(bytes: ByteArray, offset: number?, count: number?): { Word64 }
	local start = offset or 1
	local n = count or ((#bytes - start + 1) // 8)
	local words = table.create(n) :: { Word64 }
	for i = 1, n do
		local j = start + (i - 1) * 8
		words[i] = {
			hi = bor(bor(lshift(bytes[j], 24), lshift(bytes[j + 1], 16)), bor(lshift(bytes[j + 2], 8), bytes[j + 3])),
			lo = bor(bor(lshift(bytes[j + 4], 24), lshift(bytes[j + 5], 16)), bor(lshift(bytes[j + 6], 8), bytes[j + 7]))
		}
	end
	return words
end

local function words64_to_bytes_be(words: { Word64 }): ByteArray
	local bytes = table.create(#words * 8) :: ByteArray
	for i = 1, #words do
		local w, j = words[i], (i - 1) * 8
		local hi, lo = w.hi, w.lo
		bytes[j + 1], bytes[j + 2], bytes[j + 3], bytes[j + 4] = extract(hi, 24, 8), extract(hi, 16, 8), extract(hi, 8, 8), extract(hi, 0, 8)
		bytes[j + 5], bytes[j + 6], bytes[j + 7], bytes[j + 8] = extract(lo, 24, 8), extract(lo, 16, 8), extract(lo, 8, 8), extract(lo, 0, 8)
	end
	return bytes
end

local function xor_bytes(a: ByteArray, b: ByteArray): ByteArray
	local len = if #a < #b then #a else #b
	local result = table.create(len) :: ByteArray
	for i = 1, len do result[i] = bxor(a[i], b[i]) end
	return result
end

local function xor_bytes_inplace(a: ByteArray, b: ByteArray): ()
	local len = if #a < #b then #a else #b
	for i = 1, len do a[i] = bxor(a[i], b[i]) end
end

local function copy_bytes(src: ByteArray, srcOffset: number?, dstOffset: number?, count: number?): ByteArray
	local sOff = srcOffset or 1
	local dOff = dstOffset or 1
	local n = count or (#src - sOff + 1)
	local dst = table.create(dOff + n - 1) :: ByteArray
	for i = 1, n do dst[dOff + i - 1] = src[sOff + i - 1] end
	return dst
end

local function zero_bytes(count: number): ByteArray
	local bytes = table.create(count) :: ByteArray
	for i = 1, count do bytes[i] = 0 end
	return bytes
end

local function constant_time_compare(a: ByteArray, b: ByteArray): boolean
	if #a ~= #b then return false end
	local diff = 0
	for i = 1, #a do diff = bor(diff, bxor(a[i], b[i])) end
	return diff == 0
end

local function secure_zero(arr: ByteArray): ()
	for i = 1, #arr do arr[i] = 0 end
	local _ = arr[1]
end

local function string_to_bytes(s: string): ByteArray
	local bytes = table.create(#s) :: ByteArray
	for i = 1, #s do bytes[i] = string.byte(s, i) end
	return bytes
end

local function bytes_to_string(bytes: ByteArray): string
	local chars = table.create(#bytes)
	for i = 1, #bytes do chars[i] = string.char(bytes[i]) end
	return table.concat(chars)
end

local function bytes_to_hex(bytes: ByteArray): string
	local hex = table.create(#bytes)
	for i = 1, #bytes do hex[i] = string.format("%02x", bytes[i]) end
	return table.concat(hex)
end

local function hex_to_bytes(hex: string): ByteArray
	local len = #hex // 2
	local bytes = table.create(len) :: ByteArray
	for i = 1, len do bytes[i] = tonumber(string.sub(hex, i * 2 - 1, i * 2), 16) or 0 end
	return bytes
end

-- Galois Field multiplication for Aes (GF(2^8) with polynomial x^8 + x^4 + x^3 + x + 1)
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

-- for aes mixcolumns
local function create_gf_mul_table(n: number): { number }
	local t = table.create(256) :: { number }
	for i = 0, 255 do t[i] = gf_mul(i, n) end
	return t
end

return {
	WORD32_MAX = WORD32_MAX,

	and32 = and32, or32 = or32, xor32 = xor32, not32 = not32,
	shl32 = shl32, shr32 = shr32, rol32 = rol32, ror32 = ror32,
	xor32_3 = xor32_3, xor32_4 = xor32_4, xor32_5 = xor32_5,

	word64 = word64, word64_from_bytes = word64_from_bytes, word64_to_bytes = word64_to_bytes,
	and64 = and64, or64 = or64, xor64 = xor64, not64 = not64,
	xor64_3 = xor64_3, xor64_5 = xor64_5,
	add64 = add64, add64_3 = add64_3, add64_4 = add64_4, add64_5 = add64_5,
	shl64 = shl64, shr64 = shr64, rol64 = rol64, ror64 = ror64,

	bytes_to_word32_be = bytes_to_word32_be, word32_to_bytes_be = word32_to_bytes_be,
	bytes_to_word32_le = bytes_to_word32_le, word32_to_bytes_le = word32_to_bytes_le,
	bytes_to_words32_be = bytes_to_words32_be, words32_to_bytes_be = words32_to_bytes_be,
	bytes_to_words32_le = bytes_to_words32_le, words32_to_bytes_le = words32_to_bytes_le,
	bytes_to_words64_be = bytes_to_words64_be, words64_to_bytes_be = words64_to_bytes_be,

	xor_bytes = xor_bytes, xor_bytes_inplace = xor_bytes_inplace,
	copy_bytes = copy_bytes, zero_bytes = zero_bytes,
	constant_time_compare = constant_time_compare, secure_zero = secure_zero,

	string_to_bytes = string_to_bytes, bytes_to_string = bytes_to_string,
	bytes_to_hex = bytes_to_hex, hex_to_bytes = hex_to_bytes,

	gf_mul = gf_mul, create_gf_mul_table = create_gf_mul_table,
}
