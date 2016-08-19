// Package present is an implementation of the PRESENT lightweight block cipher
/*

This is a mechanical translation of https://github.com/michaelkitson/Present-8bit

*/
package present

import (
	"strconv"
)

const (
	BlockSize = 8
	KeySize   = 10

	presentRounds       = 32
	presentRoundKeySize = 8
)

var sBox = [16]byte{
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2}

var sBoxInverse = [16]byte{
	0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA}

type KeySizeError int

func (k KeySizeError) Error() string { return "present: invalid key size " + strconv.Itoa(int(k)) }

type Cipher struct {
	roundKeys [presentRounds][presentRoundKeySize]byte
}

func New(key []byte) (*Cipher, error) {

	if len(key) != KeySize {
		return nil, KeySizeError(len(key))
	}

	var cipher Cipher

	generateRoundKeys80(key, &cipher.roundKeys)

	return &cipher, nil
}

func generateRoundKeys80(suppliedKey []byte, keys *[presentRounds][presentRoundKeySize]byte) {
	// trashable key copies
	var key [KeySize]byte
	var newKey [KeySize]byte
	copy(key[:], suppliedKey[:])
	copy(keys[0][:], key[:])
	for i := byte(1); i < presentRounds; i++ {
		// rotate left 61 bits
		for j := 0; j < KeySize; j++ {
			newKey[j] = (key[(j+7)%KeySize] << 5) |
				(key[(j+8)%KeySize] >> 3)
		}
		copy(key[:], newKey[:])

		// pass leftmost 4-bits through sBox
		key[0] = (sBox[key[0]>>4] << 4) | (key[0] & 0xF)

		// xor roundCounter into bits 15 through 19
		key[8] ^= i << 7 // bit 15
		key[7] ^= i >> 1 // bits 19-16

		copy(keys[i][:], key[:])
	}
}

func addRoundKey(block []byte, roundKey *[8]byte) {
	for i := 0; i < BlockSize; i++ {
		block[i] ^= roundKey[i]
	}
}

func pLayer(block []byte) {
	var initial [BlockSize]byte
	copy(initial[:], block[:])
	for i := byte(0); i < BlockSize; i++ {
		block[i] = 0
		for j := byte(0); j < 8; j++ {
			indexVal := 4*(i%2) + (3 - (j >> 1))
			andVal := byte(8>>(i>>1)) << ((j % 2) << 2)
			block[i] |= bool2byte((initial[indexVal]&andVal) != 0) << j
		}
	}
}

func pLayerInverse(block []byte) {
	var initial [BlockSize]byte
	copy(initial[:], block[:])
	for i := byte(0); i < BlockSize; i++ {
		block[i] = 0
		for j := byte(0); j < 8; j++ {
			indexVal := (7 - ((2 * j) % 8)) - bool2byte(i < 4)
			andVal := (7 - ((2 * i) % 8)) - bool2byte(j < 4)
			block[i] |= bool2byte((initial[indexVal]&(1<<andVal)) != 0) << j
		}
	}
}

func (c *Cipher) Encrypt(dst, src []byte) {
	copy(dst, src)
	for i := 0; i < presentRounds-1; i++ {
		addRoundKey(dst, &c.roundKeys[i])
		for j := 0; j < BlockSize; j++ {
			dst[j] = (sBox[dst[j]>>4] << 4) | sBox[dst[j]&0xF]
		}
		pLayer(dst)
	}
	addRoundKey(dst, &c.roundKeys[presentRounds-1])
}

func (c *Cipher) Decrypt(dst, src []byte) {
	copy(dst, src)
	for i := presentRounds - 1; i > 0; i-- {
		addRoundKey(dst, &c.roundKeys[i])
		pLayerInverse(dst)
		for j := 0; j < BlockSize; j++ {
			dst[j] = (sBoxInverse[dst[j]>>4] << 4) | sBoxInverse[dst[j]&0xF]
		}
	}
	addRoundKey(dst, &c.roundKeys[0])
}

func (c *Cipher) BlockSize() int { return BlockSize }

func bool2byte(b bool) byte {
	if b {
		return 1
	}
	return 0
}
