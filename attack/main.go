package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
)

var (
	hashdec = "86d950f4583cdbe4f229c6c193699613a370ae22a2b6ffe899b8c94bfa54c7e4"
	msg     = "user=magodo"

	mfmsg = "&role=admin"

	secretLen = 3
)

func main() {
	flagShowMsg := flag.Bool("msg", false, "show forged message")
	flagShowHash := flag.Bool("hash", false, "show forged hash")
	flag.Parse()

	hash, err := hex.DecodeString(hashdec)
	if err != nil {
		log.Fatal(err)
	}
	prevMsgLen := uint64(secretLen) + uint64(len(msg))
	forgedMsg := msg + string(padding(prevMsgLen)) + mfmsg

	d := restoreSha256Digest(hash, prevMsgLen+uint64(len(padding(prevMsgLen))))
	d.Write([]byte(mfmsg))
	malformedHash := d.Sum(nil)

	if *flagShowMsg {
		fmt.Print(forgedMsg)
	}

	if *flagShowHash {
		fmt.Print(hex.EncodeToString(malformedHash))
	}
}

func padding(len uint64) []byte {
	// Padding. Add a 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64 + 8]byte // padding + length buffer
	tmp[0] = 0x80
	var t uint64
	if len%64 < 56 {
		t = 56 - len%64
	} else {
		t = 64 + 56 - len%64
	}

	// Length in bits.
	len <<= 3
	padlen := tmp[:t+8]
	binary.BigEndian.PutUint64(padlen[t+0:], len)
	return padlen
}

func restoreSha256Digest(hash []byte, l uint64) *digest {
	d := New().(*digest)
	for i := range d.h {
		hash, d.h[i] = consumeUint32(hash)
	}
	d.len = l
	return d
}
