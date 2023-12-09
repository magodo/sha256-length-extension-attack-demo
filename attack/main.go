package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

var (
	hashdec   string
	msg       string
	mfmsg     string
	secretLen int

	showMsg  bool
	showHash bool
)

func main() {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "msg",
				Usage:       "The legitimate message",
				Required:    true,
				Destination: &msg,
			},
			&cli.StringFlag{
				Name:        "hash",
				Usage:       "The legitimate hash (hex decimal)",
				Required:    true,
				Destination: &hashdec,
			},
			&cli.StringFlag{
				Name:        "append",
				Usage:       "The malformed msg appended to the `msg`",
				Required:    true,
				Destination: &mfmsg,
			},
			&cli.IntFlag{
				Name:        "secret-len",
				Usage:       "The secret length",
				Required:    true,
				Destination: &secretLen,
			},
			&cli.BoolFlag{
				Name:        "show-hash",
				Usage:       "Show the forged hash",
				Destination: &showHash,
			},
			&cli.BoolFlag{
				Name:        "show-msg",
				Usage:       "Show the forged msg",
				Destination: &showMsg,
			},
		},
		Action: func(cCtx *cli.Context) error {
			hash, err := hex.DecodeString(hashdec)
			if err != nil {
				log.Fatal(err)
			}
			prevMsgLen := uint64(secretLen) + uint64(len(msg))
			forgedMsg := msg + string(padding(prevMsgLen)) + mfmsg

			d := restoreSha256Digest(hash, prevMsgLen+uint64(len(padding(prevMsgLen))))
			d.Write([]byte(mfmsg))
			malformedHash := d.Sum(nil)

			if showMsg {
				fmt.Print(forgedMsg)
			}

			if showHash {
				fmt.Print(hex.EncodeToString(malformedHash))
			}
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
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
