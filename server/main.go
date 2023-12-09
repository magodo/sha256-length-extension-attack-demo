package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	var (
		flagMsg    string
		flagSecret string
		flagHash   string
	)

	readMsg := func() (string, error) {
		if flagMsg != "" {
			return flagMsg, nil
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}

	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "secret",
				Usage:       "The secret used to generate MAC for, or verify",
				Required:    true,
				Destination: &flagSecret,
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "mac",
				Usage: "Generate MAC for the message (from stdin)",
				Action: func(cCtx *cli.Context) error {
					msg, err := readMsg()
					if err != nil {
						return err
					}
					d := sha256.New()
					d.Write([]byte(flagSecret + msg))

					fmt.Print(hex.EncodeToString(d.Sum(nil)))

					return nil
				},
			},
			{
				Name:  "verify",
				Usage: "Verify the MAC of a message (from stdin)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:        "hash",
						Usage:       "The hash of the MAC, in hexdecimal form",
						Required:    true,
						Destination: &flagHash,
					},
				},
				Action: func(cCtx *cli.Context) error {
					msg, err := readMsg()
					if err != nil {
						return err
					}
					d := sha256.New()
					d.Write([]byte(flagSecret + msg))
					expect := d.Sum(nil)
					actual, err := hex.DecodeString(flagHash)
					if err != nil {
						return err
					}
					if subtle.ConstantTimeCompare(expect, actual) != 1 {
						return errors.New("invalid hash")
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
