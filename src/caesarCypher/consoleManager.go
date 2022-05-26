package caesarCypher

import "fmt"

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

	p, err := scanPath("text")
	if err != nil {
		return err
	}

	k, err := scanKey()
	if err != nil {
		return err
	}

	c, err := newСryptographer(k)
	if err != nil {
		return err
	}

	if input == string(encryptMode) {
		return c.encode(p)
	}
	if input == string(decryptMode) {
		return c.decode(p)
	}

	return nil
}

// handleCryptoanalysisInput cryptoanalysis menu handler
func handleCryptoanalysisInput(input string) error {

	if input != string(bruteForceMode) && input != string(freqAnalysisMode) {
		fmt.Println(unknownMsg)
		return nil
	}

	p, err := scanPath("encryptedtext")
	if err != nil {
		return err
	}

	// since we don't know the key
	// we pass key == 1 to cryptographer
	c, err := newСryptographer(1)
	if err != nil {
		return err
	}

	if input == string(bruteForceMode) {
		err = c.bruteForce(p)
		if err != nil {
			return err
		}
	}

	if input == string(freqAnalysisMode) {

		fmt.Println("\nYou also need to provide helper file for analysis")
		fmt.Println("This file must be unencrypted file of the same author")

		p2, err := scanPath("same_author_text")
		if err != nil {
			return err
		}

		err = c.frequencyAnalysis(p, p2)
		if err != nil {
			return err
		}
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
