package main

import (
	caesarCypher "cct/pkg/caesarcypher"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {

	flags := parseToolFlags()

	if flags.interactive {
		os.Exit(interactiveLoop())
	}

	err := flags.validate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = flags.execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(0)
}

type toolFlags struct {
	interactive bool
	encode      string
	decode      string
	brute       bool
	freq        string
	key         int
	out         string
}

func parseToolFlags() toolFlags {
	f := toolFlags{}

	flag.StringVar(&f.encode, "e", "", "encode mode -e <filepath>")
	flag.StringVar(&f.decode, "d", "", "decode mode -d <filepath>")
	flag.StringVar(&f.out, "o", "", "output file -o <filepath>")
	flag.StringVar(&f.freq, "fq", "", "frequency analysis decoding (needs helper file) -fq <filepath>")
	flag.IntVar(&f.key, "k", 0, "the key for encoding/decoding -k <number>")
	flag.BoolVar(&f.brute, "bf", false, "brute force decoding")
	flag.BoolVar(&f.interactive, "i", false, "run tool in interactive mode")

	flag.Parse()

	return f
}

func (tf *toolFlags) validate() error {

	if tf.encode != "" && tf.decode != "" {
		return fmt.Errorf("you must choose either encode '-e' mode or decode '-d' mode, not both")
	}

	if tf.decode == "" && tf.encode == "" {
		return fmt.Errorf("no input file was provided, use '-e <filepath>' or '-d <filepath>'")
	}

	if tf.decode != "" {

		if tf.brute && tf.freq != "" {
			return fmt.Errorf(
				"you must choose either brute force '-bf' mode or frequency analysis '-fq' mode, not both")
		}

		if !tf.brute && tf.freq == "" && tf.key == 0 {
			return fmt.Errorf("no helper file was provided for frequency analysis, use '-fq <filepath>'")
		}

		if !tf.brute && tf.freq == "" && tf.key == 0 {
			return fmt.Errorf("no key was provided for decoding, use '-k <number>'")
		}
	}

	if tf.encode != "" {
		if tf.key == 0 {
			return fmt.Errorf("no key was provided for encoding, use '-k <number>'")
		}
	}

	return nil
}

func (tf *toolFlags) execute() error {

	in, err := os.Open(tf.inputFileName())
	if err != nil {
		return err
	}

	out, err := os.Create(tf.outFileName())
	if err != nil {
		return err
	}

	c, err := caesarCypher.NewСryptographer(tf.key)
	if err != nil {
		return err
	}

	defer func() {
		fmt.Printf("Processed: %s >> %s\n", in.Name(), out.Name())
		_ = out.Close()
		_ = in.Close()
	}()

	if tf.encode != "" {
		return c.NewEncoder(out).Encode(in)
	}

	if tf.decode != "" {

		if tf.key != 0 {
			return c.NewKeyDecoder(in).Decode(out)
		}

		if tf.brute {
			return c.NewBruteForceDecoder(in).Decode(out)
		}

		if tf.freq != "" {
			helper, err := os.Open(tf.freq)
			if err != nil {
				return err
			}
			defer helper.Close()

			return c.NewFreqAnalisysDecoder(in, helper).Decode(out)
		}

	}

	return nil
}

func (tf *toolFlags) outFileName() string {
	if tf.out != "" {
		return tf.out
	} else {
		return tf.prefixForFile() + filepath.Base(tf.inputFileName())
	}
}

func (tf *toolFlags) prefixForFile() string {
	switch {
	case tf.out != "":
		return ""
	case tf.decode != "":
		return "decrypted_"
	case tf.encode != "":
		return "encrypted_"
	default:
		return ""
	}
}

func (tf *toolFlags) inputFileName() string {
	if tf.decode != "" {
		return tf.decode
	} else {
		return tf.encode
	}
}
