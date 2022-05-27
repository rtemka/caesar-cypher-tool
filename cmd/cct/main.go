package main

import (
	caesarCypher "cct/pkg/caesarcypher"
	"flag"
	"fmt"
	"os"
)

// the contract for cryptographer tool
type cryptographer interface {
	Encode(path string) error
	Decode(path string) error
	BruteForce(path string) error
	FrequencyAnalysis(path, helper string) error
}

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
	var c cryptographer
	var err error

	if tf.decode != "" {

		if tf.key != 0 {
			return func() error {
				c, err = caesarCypher.NewСryptographer(tf.key)
				if err != nil {
					return err
				}
				err = c.Decode(tf.decode)
				if err != nil {
					return err
				}
				return nil
			}()
		}

		if tf.brute {
			return func() error {
				c, err = caesarCypher.NewСryptographer(0)
				if err != nil {
					return err
				}
				err = c.BruteForce(tf.decode)
				if err != nil {
					return err
				}
				return nil
			}()
		}

		if tf.freq != "" {
			return func() error {
				c, err = caesarCypher.NewСryptographer(0)
				if err != nil {
					return err
				}
				err = c.FrequencyAnalysis(tf.decode, tf.freq)
				if err != nil {
					return err
				}
				return nil
			}()
		}

	}

	if tf.encode != "" {
		if tf.key != 0 {
			return func() error {
				c, err = caesarCypher.NewСryptographer(tf.key)
				if err != nil {
					return err
				}
				err = c.Encode(tf.encode)
				if err != nil {
					return err
				}
				return nil
			}()
		}
	}

	return nil
}
