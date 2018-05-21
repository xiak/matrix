package common

import (
	"unsafe"
	"net/url"
)

func UrlEncode(addr string) (*url.URL, error) {
	u, err := url.Parse(addr)
	u.RawQuery = u.Query().Encode()
	return u, err
}

func ByteSliceToString(v []byte) string {
	return *(*string)(unsafe.Pointer(&v))
}

func StringToByteSlice(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}
