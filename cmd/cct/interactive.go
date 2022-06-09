package main

import (
	caesarCypher "cct/pkg/caesarcypher"
	"fmt"
	"os"
)

// program modes
const (
	mainMode           = 0
	encryptDecryptMode = 1
	cryptoanalysisMode = 2
	encryptMode        = 'e'
	decryptMode        = 'd'
	bruteForceMode     = 'b'
	freqAnalysisMode   = 'f'
	exitMode           = "exit"
)

const (
	unknownMsg = "Unknown input parameter. You will be redirected to main menu"
)

func interactiveLoop() int {

	for {

		printUsage(mainMode)

		in, err := scanInput()
		if err != nil {
			return errorExit(err)
		}

		err = handleInput(in, handleInputMain)
		if err != nil {
			if err.Error() == exitMode {
				fmt.Println("Goodbye")
				break
			}
			return errorExit(err)
		}
	}

	return 0
}

func errorExit(err error) int {
	fmt.Fprintln(os.Stderr, err)
	fmt.Println("type any key to terminate program: ")
	_, _ = scanInput()
	return 1
}

// printUsage prints menu for the provided program mode
func printUsage(mode int) {
	fmt.Println()

	switch mode {

	case mainMode:
		fmt.Printf("\t(Main menu)\n\tCaesar cypher program usage:\n\n")
		fmt.Printf("\tChoose program mode: (%d) Encryption/Decryption (%d) Cryptoanalysis\n\n", encryptDecryptMode, cryptoanalysisMode)
		fmt.Printf("\tType %d or %d and proceed with instructions", encryptDecryptMode, cryptoanalysisMode)

	case encryptDecryptMode:
		fmt.Printf("\tEncryption/Decryption usage:\n\n")
		fmt.Printf("\tChoose mode: (%c) Encryption (%c) Decryption\n\n", encryptMode, decryptMode)
		fmt.Printf("\tType '%c' or '%c' and proceed with instructions", encryptMode, decryptMode)

	case cryptoanalysisMode:
		fmt.Printf("\tCryptoanalysis usage:\n\n")
		fmt.Printf("\tChoose mode: (%c) Brute force (%c) Frequency Analysis\n\n", bruteForceMode, freqAnalysisMode)
		fmt.Printf("\tType '%c' or '%c' and proceed with instructions", bruteForceMode, freqAnalysisMode)

	default:
		fmt.Println(unknownMsg)
		fmt.Println()
		return
	}

	fmt.Printf(" or type '%s' to quit: ", exitMode)
}

// handleInput accepts user input, checks for exit mode condition
// and if there is none pass input to provided hendler function
func handleInput(input string, f func(string) error) error {
	if input == exitMode {
		return fmt.Errorf(exitMode)
	}

	return f(input)
}

// handleInputMain main menu handler
func handleInputMain(input string) error {

	switch input {

	case fmt.Sprint(encryptDecryptMode):

		printUsage(encryptDecryptMode)
		in, err := scanInput()
		if err != nil {
			return err
		}
		return handleInput(in, handleEncDecInput)

	case fmt.Sprint(cryptoanalysisMode):

		printUsage(cryptoanalysisMode)
		in, err := scanInput()
		if err != nil {
			return err
		}
		return handleInput(in, handleCryptoanalysisInput)

	default:
		fmt.Println(unknownMsg)
	}
	return nil
}

// handleEncDecInput encode/decode menu handler
func handleEncDecInput(input string) error {

	if input != string(encryptMode) && input != string(decryptMode) {
		fmt.Println(unknownMsg)
		return nil
	}

	inPath, err := scanPath("input_text")
	if err != nil {
		return err
	}

	fmt.Println("\nNext the output file")
	outPath, err := scanPath("output_text")
	if err != nil {
		return err
	}

	k, err := scanKey()
	if err != nil {
		return err
	}

	c, err := caesarCypher.NewСryptographer(k)
	if err != nil {
		return err
	}

	in, out, err := openInOutFiles(inPath, outPath)
	if err != nil {
		return err
	}
	defer func() {
		fmt.Printf("Processed: %s >> %s\n", in.Name(), out.Name())
		_ = in.Close()
		_ = out.Close()
	}()

	if input == string(encryptMode) {
		return c.NewEncoder(out).Encode(in)
	}
	if input == string(decryptMode) {
		return c.NewKeyDecoder(in).Decode(out)
	}

	return nil
}

func openInOutFiles(path1, path2 string) (*os.File, *os.File, error) {
	in, err := os.Open(path1)
	if err != nil {
		return nil, nil, err
	}
	out, err := os.Create(path2)
	if err != nil {
		return nil, nil, err
	}

	return in, out, nil
}

// handleCryptoanalysisInput cryptoanalysis menu handler
func handleCryptoanalysisInput(input string) error {

	if input != string(bruteForceMode) && input != string(freqAnalysisMode) {
		fmt.Println(unknownMsg)
		return nil
	}

	inPath, err := scanPath("encrypted_text")
	if err != nil {
		return err
	}

	fmt.Println("\nNext the output file")
	outPath, err := scanPath("decrypted_text")
	if err != nil {
		return err
	}

	// since we don't know the key
	// we pass key == 0 to cryptographer
	c, err := caesarCypher.NewСryptographer(0)
	if err != nil {
		return err
	}

	in, out, err := openInOutFiles(inPath, outPath)
	if err != nil {
		return err
	}
	defer func() {
		fmt.Printf("Processed: %s >> %s\n", in.Name(), out.Name())
		_ = in.Close()
		_ = out.Close()
	}()

	if input == string(bruteForceMode) {
		return c.NewBruteForceDecoder(in).Decode(out)
	}

	if input == string(freqAnalysisMode) {

		fmt.Println("\nYou also need to provide helper file for analysis")
		fmt.Println("This file must be unencrypted file of the same author")

		helperPath, err := scanPath("same_author_text")
		if err != nil {
			return err
		}
		helper, err := os.Open(helperPath)
		if err != nil {
			return err
		}
		defer helper.Close()

		return c.NewFreqAnalisysDecoder(in, helper).Decode(out)
	}
	return nil
}

// scanInput is a helper function
// that scans user input to string
func scanInput() (string, error) {
	var input string

	_, err := fmt.Scanln(&input)
	if err != nil {
		return "", err
	}
	return input, nil
}

func scanPath(prefix string) (string, error) {
	fmt.Printf("\nEnter file name (for example '%s.txt'): ", prefix)
	return scanInput()
}

func scanKey() (int, error) {
	var key int

	fmt.Print("\nEnter key: ")
	_, err := fmt.Scanln(&key)
	if err != nil {
		return 0, err
	}

	return key, nil
}
