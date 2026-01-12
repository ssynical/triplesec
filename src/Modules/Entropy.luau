--!native
--!strict
--!optimize 2

local Blake3 = require(script.Parent.Blake3) -- Credit to @daily3014 & @Xoifail (both on github) for this implementation

local os_clock = os.clock
local os_time = os.time
local math_random = math.random
local math_floor = math.floor
local string_byte = string.byte
local table_create = table.create
local table_insert = table.insert
local band, bxor, lshift, rshift = bit32.band, bit32.bxor, bit32.lshift, bit32.rshift
local lrotate = bit32.lrotate

export type ByteArray = { number }
export type EntropyPool = {
	state: { number },
	counter: number,
	reseedCount: number,
	lastReseed: number,
}

local POOL_SIZE: number = 256
local POOL_WORDS: number = 64
local RESEED_INTERVAL: number = 0.1
local MIN_POOL_SAMPLES: number = 32

local function quarter_round(a: number, b: number, c: number, d: number): (number, number, number, number)
	a = band(a + b, 0xFFFFFFFF); d = lrotate(bxor(d, a), 16)
	c = band(c + d, 0xFFFFFFFF); b = lrotate(bxor(b, c), 12)
	a = band(a + b, 0xFFFFFFFF); d = lrotate(bxor(d, a), 8)
	c = band(c + d, 0xFFFFFFFF); b = lrotate(bxor(b, c), 7)
	return a, b, c, d
end

local function chacha_block(state: { number }): { number }
	local s = table_create(16) :: { number }
	for i = 1, 16 do s[i] = state[i] end

	for _ = 1, 10 do
		s[1], s[5], s[9], s[13] = quarter_round(s[1], s[5], s[9], s[13])
		s[2], s[6], s[10], s[14] = quarter_round(s[2], s[6], s[10], s[14])
		s[3], s[7], s[11], s[15] = quarter_round(s[3], s[7], s[11], s[15])
		s[4], s[8], s[12], s[16] = quarter_round(s[4], s[8], s[12], s[16])
		s[1], s[6], s[11], s[16] = quarter_round(s[1], s[6], s[11], s[16])
		s[2], s[7], s[12], s[13] = quarter_round(s[2], s[7], s[12], s[13])
		s[3], s[8], s[9], s[14] = quarter_round(s[3], s[8], s[9], s[14])
		s[4], s[5], s[10], s[15] = quarter_round(s[4], s[5], s[10], s[15])
	end

	local out = table_create(16) :: { number }
	for i = 1, 16 do out[i] = band(s[i] + state[i], 0xFFFFFFFF) end
	return out
end

local function collect_time_entropy(): { number }
	local entropy = table_create(8) :: { number }
	local clock = os_clock()
	local time = os_time()

	local clockBits = math_floor(clock * 1000000000)
	entropy[1] = band(clockBits, 0xFFFFFFFF)
	entropy[2] = band(rshift(clockBits, 32), 0xFFFFFFFF)

	entropy[3] = band(time, 0xFFFFFFFF)
	entropy[4] = band(rshift(time, 32), 0xFFFFFFFF)

	local clock2 = os_clock()
	local jitter = math_floor((clock2 - clock) * 1000000000000)
	entropy[5] = band(jitter, 0xFFFFFFFF)

	local sum = 0
	for i = 1, 100 do sum = sum + os_clock() end
	entropy[6] = band(math_floor(sum * 1000000000), 0xFFFFFFFF)

	local t1, t2 = os_clock(), 0
	local _ = table_create(1000)
	t2 = os_clock()
	entropy[7] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	local acc = 0
	for i = 1, 1000 do acc = acc + i * os_clock() end
	entropy[8] = band(math_floor(acc), 0xFFFFFFFF)

	return entropy
end

-- This is seeded by roblox with okay-ish entropy
local function collect_random_entropy(): { number }
	local entropy = table_create(16) :: { number }
	for i = 1, 16 do
		entropy[i] = band(math_floor(math_random() * 0xFFFFFFFF), 0xFFFFFFFF)
	end
	return entropy
end

local function collect_string_entropy(): { number }
	local entropy = table_create(8) :: { number }
	local testStr = string.rep("x", 10000)

	local t1 = os_clock()
	local _ = string.reverse(testStr)
	local t2 = os_clock()
	entropy[1] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	t1 = os_clock()
	_ = string.upper(testStr)
	t2 = os_clock()
	entropy[2] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	t1 = os_clock()
	_ = string.lower(testStr)
	t2 = os_clock()
	entropy[3] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	t1 = os_clock()
	_ = string.find(testStr, "y")
	t2 = os_clock()
	entropy[4] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	local hash = 0x811C9DC5
	for i = 1, 100 do
		hash = bxor(hash, string_byte(testStr, i))
		hash = band(hash * 0x01000193, 0xFFFFFFFF)
	end
	entropy[5] = hash

	t1 = os_clock()
	_ = string.gsub(testStr, "x", "y")
	t2 = os_clock()
	entropy[6] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	t1 = os_clock()
	_ = string.sub(testStr, 1, 5000)
	t2 = os_clock()
	entropy[7] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	entropy[8] = band(math_floor(os_clock() * 1000000000), 0xFFFFFFFF)

	return entropy
end

local function collect_table_entropy(): { number }
	local entropy = table_create(8) :: { number }

	local t1 = os_clock()
	local tbl = table_create(10000) :: { number }
	for i = 1, 10000 do tbl[i] = i end
	local t2 = os_clock()
	entropy[1] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	t1 = os_clock()
	table.sort(tbl, function(a: number, b: number) return a > b end)
	t2 = os_clock()
	entropy[2] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	t1 = os_clock()
	local sum = 0
	for _, v in ipairs(tbl) do sum = sum + v end
	t2 = os_clock()
	entropy[3] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)
	entropy[4] = band(sum, 0xFFFFFFFF)

	t1 = os_clock()
	local tbl2 = table.clone(tbl)
	t2 = os_clock()
	entropy[5] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	t1 = os_clock()
	table.clear(tbl2)
	t2 = os_clock()
	entropy[6] = band(math_floor((t2 - t1) * 1000000000000), 0xFFFFFFFF)

	entropy[7] = band(math_floor(os_clock() * 1000000000), 0xFFFFFFFF)
	entropy[8] = band(math_floor(math_random() * 0xFFFFFFFF), 0xFFFFFFFF)

	return entropy
end

local function mix_into_pool(pool: { number }, entropy: { number }): ()
	-- Gather all entropy into a byte array for the BLAKE3 extraction
	local entropyLen = #entropy
	local poolLen = #pool
	local totalWords = entropyLen + poolLen
	local inputBytes = table_create(totalWords * 4) :: ByteArray

	for i = 1, poolLen do
		local word = pool[i]
		local offset = (i - 1) * 4
		inputBytes[offset + 1] = band(word, 0xFF)
		inputBytes[offset + 2] = band(rshift(word, 8), 0xFF)
		inputBytes[offset + 3] = band(rshift(word, 16), 0xFF)
		inputBytes[offset + 4] = band(rshift(word, 24), 0xFF)
	end

	for i = 1, entropyLen do
		local word = entropy[i]
		local offset = (poolLen + i - 1) * 4
		inputBytes[offset + 1] = band(word, 0xFF)
		inputBytes[offset + 2] = band(rshift(word, 8), 0xFF)
		inputBytes[offset + 3] = band(rshift(word, 16), 0xFF)
		inputBytes[offset + 4] = band(rshift(word, 24), 0xFF)
	end

	-- Use BLAKE3 as our entropy extractor
	local extracted = Blake3.hash(inputBytes, POOL_SIZE)

	-- Update the pool with said extracted entropy
	for i = 1, POOL_WORDS do
		local offset = (i - 1) * 4
		pool[i] = extracted[offset + 1] + extracted[offset + 2] * 256 + extracted[offset + 3] * 65536 + extracted[offset + 4] * 16777216
	end
end

local function create_pool(): EntropyPool
	local state = table_create(POOL_WORDS) :: { number }

	state[1], state[2], state[3], state[4] = 0x61707865, 0x3320646E, 0x79622D32, 0x6B206574

	local timeEntropy = collect_time_entropy()
	local randomEntropy = collect_random_entropy()

	for i = 5, POOL_WORDS do
		local te = timeEntropy[((i - 5) % #timeEntropy) + 1] or 0
		local re = randomEntropy[((i - 5) % #randomEntropy) + 1] or 0
		state[i] = bxor(te, re)
	end

	for _ = 1, 10 do
		mix_into_pool(state, collect_time_entropy())
		mix_into_pool(state, collect_random_entropy())
	end

	return {
		state = state,
		counter = 0,
		reseedCount = 0,
		lastReseed = os_clock(),
	}
end

local function reseed_pool(pool: EntropyPool): ()
	mix_into_pool(pool.state, collect_time_entropy())
	mix_into_pool(pool.state, collect_random_entropy())
	mix_into_pool(pool.state, collect_string_entropy())
	mix_into_pool(pool.state, collect_table_entropy())

	pool.reseedCount = pool.reseedCount + 1
	pool.lastReseed = os_clock()
end

local function generate_bytes(pool: EntropyPool, count: number): ByteArray
	local bytes = table_create(count) :: ByteArray
	local bytesGenerated = 0

	local now = os_clock()
	if now - pool.lastReseed > RESEED_INTERVAL then reseed_pool(pool) end

	while bytesGenerated < count do
		pool.counter = band(pool.counter + 1, 0xFFFFFFFF)
		pool.state[13] = pool.counter
		pool.state[14] = band(pool.state[14] + (if pool.counter == 0 then 1 else 0), 0xFFFFFFFF)

		local block = chacha_block(pool.state)

		for i = 1, 16 do
			if bytesGenerated >= count then break end
			local word = block[i]
			for j = 0, 3 do
				if bytesGenerated >= count then break end
				bytesGenerated = bytesGenerated + 1
				bytes[bytesGenerated] = band(rshift(word, j * 8), 0xFF)
			end
		end

		-- Here, we mix the output back into the state to keep... secrecy.
		for i = 1, 8 do pool.state[i + 4] = bxor(pool.state[i + 4], block[i]) end
	end

	return bytes
end

local function generate_word32(pool: EntropyPool): number
	local bytes = generate_bytes(pool, 4)
	return bxor(bxor(bytes[1], lshift(bytes[2], 8)), bxor(lshift(bytes[3], 16), lshift(bytes[4], 24)))
end

-- [min, max]
local function generate_range(pool: EntropyPool, min: number, max: number): number
	local range = max - min + 1
	local bytes = generate_bytes(pool, 4)
	local value = bxor(bxor(bytes[1], lshift(bytes[2], 8)), bxor(lshift(bytes[3], 16), lshift(bytes[4], 24)))
	return min + (value % range)
end

-- Fisher-Yates shuffle using CSPRNG
local function shuffle<T>(pool: EntropyPool, arr: { T }): { T }
	local n = #arr
	local result = table.clone(arr) :: { T }
	for i = n, 2, -1 do
		local j = generate_range(pool, 1, i)
		result[i], result[j] = result[j], result[i]
	end
	return result
end

local globalPool: EntropyPool? = nil

local function get_global_pool(): EntropyPool
	if not globalPool then globalPool = create_pool() end
	return globalPool :: EntropyPool
end

local function random_bytes(count: number): ByteArray return generate_bytes(get_global_pool(), count) end
local function random_word32(): number return generate_word32(get_global_pool()) end
local function random_range(min: number, max: number): number return generate_range(get_global_pool(), min, max) end
local function random_shuffle<T>(arr: { T }): { T } return shuffle(get_global_pool(), arr) end

local function add_entropy(data: ByteArray): ()
	local pool = get_global_pool()
	local words = table_create(math.ceil(#data / 4)) :: { number }
	for i = 1, #data, 4 do
		local w = data[i] or 0
		if data[i + 1] then w = bxor(w, lshift(data[i + 1], 8)) end
		if data[i + 2] then w = bxor(w, lshift(data[i + 2], 16)) end
		if data[i + 3] then w = bxor(w, lshift(data[i + 3], 24)) end
		words[math.ceil(i / 4)] = w
	end
	mix_into_pool(pool.state, words)
end

local function force_reseed(): () reseed_pool(get_global_pool()) end

local function get_entropy_estimate(): number
	local pool = get_global_pool()
	return pool.reseedCount * 256 + pool.counter * 64
end

return {
	create_pool = create_pool,
	reseed_pool = reseed_pool,
	generate_bytes = generate_bytes,
	generate_word32 = generate_word32,
	generate_range = generate_range,
	shuffle = shuffle,

	random_bytes = random_bytes,
	random_word32 = random_word32,
	random_range = random_range,
	random_shuffle = random_shuffle,
	add_entropy = add_entropy,
	force_reseed = force_reseed,
	get_entropy_estimate = get_entropy_estimate,

	collect_time_entropy = collect_time_entropy,
	collect_random_entropy = collect_random_entropy,
	collect_string_entropy = collect_string_entropy,
	collect_table_entropy = collect_table_entropy,
}