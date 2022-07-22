package internal

import (
	"strings"
)

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// Generates a string key to use as a unique key in maps
func calculateKey(elements ...string) (key string) {
	var concat []string
	for _, e := range elements {
		concat = append(concat, e)
	}
	key = strings.Join(concat, "")
	return key
}

// Returns true if properties are not equal and both have non zero values
func differs(a interface{}, b interface{}) bool {
	aint, aok := a.(int)
	bint, bok := b.(int)
	if aok && bok {
		if aint == 0 || bint == 0 || aint == bint {
			return false
		}
	}
	astr, aok := a.(string)
	bstr, bok := b.(string)
	if aok && bok {
		if astr == "" || bstr == "" || aint == bint {
			return false
		}
	}
	return true
}

// function to check similar bssid strings, with no more than 2 characters different
func similar(a string, b string) bool {
	// if length no matches there is no similarity
	if len(a) != len(b) {
		return false
	}
	badCounter := 0
	for idx := 0; idx < len(a); idx++ {
		if a[idx] != b[idx] {
			badCounter += 1
			if badCounter > 2 {
				return false
			}
		}
	}
	return true
}
