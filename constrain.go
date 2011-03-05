package main

import (
	"strings"
	"unicode"
)

func isNotAlNum(rune int) bool {
	if unicode.IsLetter(rune) {
		return false
	}
	if unicode.IsDigit(rune) {
		return false
	}
	return true
}

func rotate(arr []string, amount byte) []string {
	for i := byte(0); i < amount; i++ {
		arr = append(arr, arr[0])
		arr = arr[1:]
	}
	return arr
}

func between(min, interval, offset byte) byte {
	return min + offset%interval
}

func constrain(hash string, size int, nonalnum bool) string {
	hash = strings.TrimRight(hash, "=") // PwdHash uses "" for pad
	start := size - 4
	rv := hash[:start]
	extras := strings.Split(hash[start:], "", -1)

	nextExtra := func() string {
		if len(extras) > 0 {
			rv := extras[0]
			extras = extras[1:]
			return rv
		}
		return ""
	}
	nextBetween := func(base int, interval byte) string {
		return string([]byte{between(byte(base), interval, nextExtra()[0])})
	}

	if strings.IndexFunc(rv, unicode.IsUpper) >= 0 {
		rv += nextExtra()
	} else {
		rv += nextBetween('A', 26)
	}
	if strings.IndexFunc(rv, unicode.IsLower) >= 0 {
		rv += nextExtra()
	} else {
		rv += nextBetween('a', 26)
	}
	if strings.IndexFunc(rv, unicode.IsDigit) >= 0 {
		rv += nextExtra()
	} else {
		rv += nextBetween('0', 10)
	}
	if nonalnum && strings.IndexFunc(rv, isNotAlNum) >= 0 {
		rv += nextExtra()
	} else {
		rv += "+"
	}
	if !nonalnum {
		for i := strings.IndexFunc(rv, isNotAlNum); i >= 0; i = strings.IndexFunc(rv, isNotAlNum) {
			rv = rv[:i] + nextBetween('A', 26) + rv[i+1:]
		}
	}

	list := strings.Split(rv, "", -1)
	list = rotate(list, nextExtra()[0])
	rv = strings.Join(list, "")
	return rv
}
