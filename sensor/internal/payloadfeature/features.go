package payloadfeature

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
)

const (
	fnvOffset    uint64 = 14695981039346656037
	fnvPrime     uint64 = 1099511628211
	prefixBytes         = 32
	shingleBytes        = 3
)

type Features struct {
	Hash           string
	PrefixHash     string
	Length         uint32
	Entropy        float64
	PrintableRatio float64
	SimHash        string
	Version        string
}

func Compute(payload []byte) Features {
	if len(payload) == 0 {
		return Features{}
	}
	full := sha256.Sum256(payload)
	prefix := payload
	if len(prefix) > prefixBytes {
		prefix = prefix[:prefixBytes]
	}
	prefixDigest := sha256.Sum256(prefix)
	counts := [256]int{}
	printable := 0
	for _, value := range payload {
		counts[value]++
		if (value >= 0x20 && value <= 0x7e) || value == 9 || value == 10 || value == 13 {
			printable++
		}
	}
	entropy := 0.0
	length := float64(len(payload))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}
	return Features{
		Hash:           hex.EncodeToString(full[:]),
		PrefixHash:     hex.EncodeToString(prefixDigest[:]),
		Length:         uint32(len(payload)),
		Entropy:        round4(entropy),
		PrintableRatio: round4(float64(printable) / length),
		SimHash:        fmt.Sprintf("%016x", simHash(payload)),
		Version:        "1",
	}
}

func simHash(payload []byte) uint64 {
	votes := [64]int{}
	apply := func(shingle []byte) {
		hashed := fnv1a64(shingle)
		for bit := 0; bit < 64; bit++ {
			if hashed&(uint64(1)<<bit) != 0 {
				votes[bit]++
			} else {
				votes[bit]--
			}
		}
	}
	if len(payload) < shingleBytes {
		apply(payload)
	} else {
		for index := 0; index <= len(payload)-shingleBytes; index++ {
			apply(payload[index : index+shingleBytes])
		}
	}
	var result uint64
	for bit, vote := range votes {
		if vote >= 0 {
			result |= uint64(1) << bit
		}
	}
	return result
}

func fnv1a64(value []byte) uint64 {
	result := fnvOffset
	for _, item := range value {
		result ^= uint64(item)
		result *= fnvPrime
	}
	return result
}

func round4(value float64) float64 {
	return math.Round(value*10000) / 10000
}
