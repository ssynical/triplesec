--!native
--!strict
--!optimize 2

--[[

Credit to @Xoifail and @daily3014 for this implementation.
You can find the full, original source at https://github.com/daily3014/rbx-cryptography/blob/main/src/Hashing/Blake3.luau

]]

local band, bxor = bit32.band, bit32.bxor
local lrotate = bit32.lrotate
local table_create = table.create

export type ByteArray = { number }

local BLOCK_SIZE: number = 64
local CV_SIZE: number = 32
local EXTENDED_CV_SIZE: number = 64
local MAX_STACK_DEPTH: number = 64

local CHUNK_START: number = 0x01
local CHUNK_END: number = 0x02
local PARENT_FLAG: number = 0x04
local ROOT_FLAG: number = 0x08

local IV: { number } = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }

local function bytes_to_u32(data: ByteArray, offset: number): number
	return data[offset] + data[offset + 1] * 256 + data[offset + 2] * 65536 + data[offset + 3] * 16777216
end

local function u32_to_bytes(value: number, output: ByteArray, offset: number): ()
	output[offset] = band(value, 0xFF)
	output[offset + 1] = band(value / 256, 0xFF)
	output[offset + 2] = band(value / 65536, 0xFF)
	output[offset + 3] = band(value / 16777216, 0xFF)
end

local function compress(hash: { number }, block: ByteArray, blockOffset: number, counter: number, blockLen: number, flags: number, isFull: boolean?): { number }
	local h0, h1, h2, h3, h4, h5, h6, h7 = hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7], hash[8]
	local v0, v1, v2, v3 = h0, h1, h2, h3
	local v4, v5, v6, v7 = h4, h5, h6, h7
	local v8, v9, v10, v11 = IV[1], IV[2], IV[3], IV[4]
	local v12 = band(counter, 0xFFFFFFFF)
	local v13 = math.floor(counter / 0x100000000)
	local v14, v15 = blockLen, flags

	local m0 = bytes_to_u32(block, blockOffset)
	local m1 = bytes_to_u32(block, blockOffset + 4)
	local m2 = bytes_to_u32(block, blockOffset + 8)
	local m3 = bytes_to_u32(block, blockOffset + 12)
	local m4 = bytes_to_u32(block, blockOffset + 16)
	local m5 = bytes_to_u32(block, blockOffset + 20)
	local m6 = bytes_to_u32(block, blockOffset + 24)
	local m7 = bytes_to_u32(block, blockOffset + 28)
	local m8 = bytes_to_u32(block, blockOffset + 32)
	local m9 = bytes_to_u32(block, blockOffset + 36)
	local m10 = bytes_to_u32(block, blockOffset + 40)
	local m11 = bytes_to_u32(block, blockOffset + 44)
	local m12 = bytes_to_u32(block, blockOffset + 48)
	local m13 = bytes_to_u32(block, blockOffset + 52)
	local m14 = bytes_to_u32(block, blockOffset + 56)
	local m15 = bytes_to_u32(block, blockOffset + 60)

	local temp
	for round = 1, 7 do
		v0 = band(v0 + v4 + m0, 0xFFFFFFFF); v12 = lrotate(bxor(v12, v0), 16)
		v8 = band(v8 + v12, 0xFFFFFFFF); v4 = lrotate(bxor(v4, v8), 20)
		v0 = band(v0 + v4 + m1, 0xFFFFFFFF); v12 = lrotate(bxor(v12, v0), 24)
		v8 = band(v8 + v12, 0xFFFFFFFF); v4 = lrotate(bxor(v4, v8), 25)

		v1 = band(v1 + v5 + m2, 0xFFFFFFFF); v13 = lrotate(bxor(v13, v1), 16)
		v9 = band(v9 + v13, 0xFFFFFFFF); v5 = lrotate(bxor(v5, v9), 20)
		v1 = band(v1 + v5 + m3, 0xFFFFFFFF); v13 = lrotate(bxor(v13, v1), 24)
		v9 = band(v9 + v13, 0xFFFFFFFF); v5 = lrotate(bxor(v5, v9), 25)

		v2 = band(v2 + v6 + m4, 0xFFFFFFFF); v14 = lrotate(bxor(v14, v2), 16)
		v10 = band(v10 + v14, 0xFFFFFFFF); v6 = lrotate(bxor(v6, v10), 20)
		v2 = band(v2 + v6 + m5, 0xFFFFFFFF); v14 = lrotate(bxor(v14, v2), 24)
		v10 = band(v10 + v14, 0xFFFFFFFF); v6 = lrotate(bxor(v6, v10), 25)

		v3 = band(v3 + v7 + m6, 0xFFFFFFFF); v15 = lrotate(bxor(v15, v3), 16)
		v11 = band(v11 + v15, 0xFFFFFFFF); v7 = lrotate(bxor(v7, v11), 20)
		v3 = band(v3 + v7 + m7, 0xFFFFFFFF); v15 = lrotate(bxor(v15, v3), 24)
		v11 = band(v11 + v15, 0xFFFFFFFF); v7 = lrotate(bxor(v7, v11), 25)

		v0 = band(v0 + v5 + m8, 0xFFFFFFFF); v15 = lrotate(bxor(v15, v0), 16)
		v10 = band(v10 + v15, 0xFFFFFFFF); v5 = lrotate(bxor(v5, v10), 20)
		v0 = band(v0 + v5 + m9, 0xFFFFFFFF); v15 = lrotate(bxor(v15, v0), 24)
		v10 = band(v10 + v15, 0xFFFFFFFF); v5 = lrotate(bxor(v5, v10), 25)

		v1 = band(v1 + v6 + m10, 0xFFFFFFFF); v12 = lrotate(bxor(v12, v1), 16)
		v11 = band(v11 + v12, 0xFFFFFFFF); v6 = lrotate(bxor(v6, v11), 20)
		v1 = band(v1 + v6 + m11, 0xFFFFFFFF); v12 = lrotate(bxor(v12, v1), 24)
		v11 = band(v11 + v12, 0xFFFFFFFF); v6 = lrotate(bxor(v6, v11), 25)

		v2 = band(v2 + v7 + m12, 0xFFFFFFFF); v13 = lrotate(bxor(v13, v2), 16)
		v8 = band(v8 + v13, 0xFFFFFFFF); v7 = lrotate(bxor(v7, v8), 20)
		v2 = band(v2 + v7 + m13, 0xFFFFFFFF); v13 = lrotate(bxor(v13, v2), 24)
		v8 = band(v8 + v13, 0xFFFFFFFF); v7 = lrotate(bxor(v7, v8), 25)

		v3 = band(v3 + v4 + m14, 0xFFFFFFFF); v14 = lrotate(bxor(v14, v3), 16)
		v9 = band(v9 + v14, 0xFFFFFFFF); v4 = lrotate(bxor(v4, v9), 20)
		v3 = band(v3 + v4 + m15, 0xFFFFFFFF); v14 = lrotate(bxor(v14, v3), 24)
		v9 = band(v9 + v14, 0xFFFFFFFF); v4 = lrotate(bxor(v4, v9), 25)

		if round ~= 7 then
			temp = m2; m2 = m3; m3 = m10; m10 = m12; m12 = m9; m9 = m11; m11 = m5; m5 = m0; m0 = temp
			temp = m6; m6 = m4; m4 = m7; m7 = m13; m13 = m14; m14 = m15; m15 = m8; m8 = m1; m1 = temp
		end
	end

	if isFull then
		return {
			bxor(v0, v8), bxor(v1, v9), bxor(v2, v10), bxor(v3, v11),
			bxor(v4, v12), bxor(v5, v13), bxor(v6, v14), bxor(v7, v15),
			bxor(v8, h0), bxor(v9, h1), bxor(v10, h2), bxor(v11, h3),
			bxor(v12, h4), bxor(v13, h5), bxor(v14, h6), bxor(v15, h7),
		}
	else
		return {
			bxor(v0, v8), bxor(v1, v9), bxor(v2, v10), bxor(v3, v11),
			bxor(v4, v12), bxor(v5, v13), bxor(v6, v14), bxor(v7, v15),
		}
	end
end

local function hash(message: ByteArray, outputLen: number?): ByteArray
	local outLen = outputLen or 32
	local msgLen = #message

	local paddedLen = math.max(64, math.ceil(msgLen / 64) * 64)
	local padded = table_create(paddedLen) :: ByteArray
	for i = 1, msgLen do padded[i] = message[i] end
	for i = msgLen + 1, paddedLen do padded[i] = 0 end

	local cv = table.clone(IV)
	local stackCvs: { { number } } = {}
	local stackSize = 0
	local counter = 0
	local chunkNum = 0
	local startFlag = CHUNK_START
	local endFlag = 0

	local numBlocks = paddedLen // BLOCK_SIZE
	for blockIdx = 0, numBlocks - 2 do
		local blockOff = blockIdx * BLOCK_SIZE + 1
		local flags = startFlag + endFlag
		cv = compress(cv, padded, blockOff, counter, BLOCK_SIZE, flags)
		startFlag = 0
		chunkNum = chunkNum + 1

		if chunkNum == 15 then
			endFlag = CHUNK_END
		elseif chunkNum == 16 then
			local mergeCv = cv
			local mergeAmount = counter + 1

			while mergeAmount % 2 == 0 do
				stackSize = stackSize - 1
				local popCv = stackCvs[stackSize + 1]
				local mergeBlock = table_create(64) :: ByteArray
				for i = 1, 8 do u32_to_bytes(popCv[i], mergeBlock, (i - 1) * 4 + 1) end
				for i = 1, 8 do u32_to_bytes(mergeCv[i], mergeBlock, 32 + (i - 1) * 4 + 1) end
				mergeCv = compress(IV, mergeBlock, 1, 0, BLOCK_SIZE, PARENT_FLAG)
				mergeAmount = mergeAmount // 2
			end

			stackSize = stackSize + 1
			stackCvs[stackSize] = mergeCv
			cv = table.clone(IV)
			startFlag = CHUNK_START
			counter = counter + 1
			chunkNum = 0
			endFlag = 0
		end
	end

	local lastBlockOff = (numBlocks - 1) * BLOCK_SIZE + 1
	local lastLen = if msgLen == 0 then 0 else ((msgLen - 1) % BLOCK_SIZE + 1)

	local outputCv: { number }
	local outputBlock = table_create(64) :: ByteArray
	local outputLen2: number
	local outputFlags: number

	if counter > 0 then
		local flags = startFlag + CHUNK_END
		local mergeCv = compress(cv, padded, lastBlockOff, counter, lastLen, flags)

		for i = stackSize, 2, -1 do
			local stackCv = stackCvs[i]
			local mergeBlock = table_create(64) :: ByteArray
			for j = 1, 8 do u32_to_bytes(stackCv[j], mergeBlock, (j - 1) * 4 + 1) end
			for j = 1, 8 do u32_to_bytes(mergeCv[j], mergeBlock, 32 + (j - 1) * 4 + 1) end
			mergeCv = compress(IV, mergeBlock, 1, 0, BLOCK_SIZE, PARENT_FLAG)
		end

		outputCv = IV
		local firstStackCv = stackCvs[1]
		for i = 1, 8 do u32_to_bytes(firstStackCv[i], outputBlock, (i - 1) * 4 + 1) end
		for i = 1, 8 do u32_to_bytes(mergeCv[i], outputBlock, 32 + (i - 1) * 4 + 1) end
		outputLen2 = BLOCK_SIZE
		outputFlags = ROOT_FLAG + PARENT_FLAG
	else
		outputCv = cv
		for i = 1, 64 do outputBlock[i] = padded[lastBlockOff + i - 1] or 0 end
		outputLen2 = lastLen
		outputFlags = startFlag + CHUNK_END + ROOT_FLAG
	end

	local output = table_create(outLen) :: ByteArray
	local outputOffset = 0

	for idx = 0, math.ceil(outLen / BLOCK_SIZE) do
		local digest = compress(outputCv, outputBlock, 1, idx, outputLen2, outputFlags, true)
		local bytesToCopy = math.min(BLOCK_SIZE, outLen - outputOffset)

		for i = 1, bytesToCopy do
			local wordIdx = ((i - 1) // 4) + 1
			local byteIdx = (i - 1) % 4
			output[outputOffset + i] = band(digest[wordIdx] / (256 ^ byteIdx), 0xFF)
		end

		outputOffset = outputOffset + bytesToCopy
		if outputOffset >= outLen then break end
	end

	return output
end

local function hash_hex(message: ByteArray, outputLen: number?): string
	local result = hash(message, outputLen)
	local hex = table_create(#result)
	for i = 1, #result do hex[i] = string.format("%02x", result[i]) end
	return table.concat(hex)
end

return {
	BLOCK_SIZE = BLOCK_SIZE,
	DIGEST_SIZE = CV_SIZE,
	hash = hash,
	hash_hex = hash_hex,
}