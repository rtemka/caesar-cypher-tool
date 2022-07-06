package main

import (
	caesarCypher "cct/pkg/caesarcypher"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

func main() {

	flags := parseToolFlags()

	if len(os.Args) == 1 {
		flag.PrintDefaults()
		os.Exit(1)
	}

	tool, err := newTool(flags)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if tool.flags.interactive {
		os.Exit(tool.interactiveLoop())
	}

	if err := tool.execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	os.Exit(0)
}

type tool struct {
	flags  toolFlags
	logger *log.Logger
}

func newTool(flags toolFlags) (*tool, error) {
	err := flags.validate()
	if err != nil {
		return nil, err
	}

	l := func() *log.Logger {
		if flags.verbose {
			return log.New(os.Stdout, "[cypher tool] | ", log.Lmsgprefix)
		} else if flags.interactive {
			return log.New(os.Stdout, "", 0)
		} else {
			return log.New(io.Discard, "", 0)
		}
	}()

	return &tool{flags: flags, logger: l}, nil
}

type toolFlags struct {
	interactive bool
	verbose     bool
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
	flag.BoolVar(&f.verbose, "v", false, "verbose output")

	flag.Parse()

	return f
}

func (tf *toolFlags) validate() error {

	if tf.interactive {
		return nil
	}

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

func (t *tool) execute() error {

	in, err := os.Open(t.flags.inputFileName())
	if err != nil {
		return err
	}

	out, err := os.Create(t.flags.outFileName())
	if err != nil {
		return err
	}

	c, err := caesarCypher.NewCypher(t.flags.key, t.logger)
	if err != nil {
		return err
	}

	defer func() {
		t.logger.Printf("Processed: %s > %s\n", in.Name(), out.Name())
		_ = out.Close()
		_ = in.Close()
	}()

	if t.flags.encode != "" {
		return c.NewEncrypter(out).Encrypt(in)
	}

	if t.flags.decode != "" {

		if t.flags.key != 0 {
			return c.NewDecrypter(in).Decrypt(out)
		}

		if t.flags.brute {
			return c.NewBruteForceDecrypter(in).Decrypt(out)
		}

		if t.flags.freq != "" {
			helper, err := os.Open(t.flags.freq)
			if err != nil {
				return err
			}
			defer helper.Close()

			return c.NewFreqAnalisysDecrypter(in, helper).Decrypt(out)
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
