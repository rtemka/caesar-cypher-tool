package caesarCypher

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"unicode/utf8"
)

// in most texts
const mostFrequentChar = ' '

// if we found rune that is not in our alphabet
const skipRune = '~'

// cryptoAlphabet returns slice of runes that is our program working with
func cryptoAlphabet() []rune {
	return []rune{'А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М',
		'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ', 'Ы', 'Ь', 'Э', 'Ю', 'Я',
		'а', 'б', 'в', 'г', 'д', 'е', 'ё', 'ж', 'з', 'и', 'й', 'к', 'л', 'м',
		'н', 'о', 'п', 'р', 'с', 'т', 'у', 'ф', 'х', 'ц', 'ч', 'ш', 'щ', 'ъ', 'ы', 'ь', 'э', 'ю', 'я',
		':', ',', '"', '?', '-', '—', '.', '!', ' '}
}

// entity holding cypher logic
type cryptographer struct {
	lookup   map[rune]int
	alphabet []rune
	key      int
}

type Encoder struct {
	c *cryptographer
	w io.Writer
}

type Decoder struct {
	c    *cryptographer
	r    io.Reader
	hr   io.Reader               // helper stream
	decf func(w io.Writer) error // decode function
}

// NewСryptographer returns instance of cryptographer
func NewСryptographer(key int) (*cryptographer, error) {

	// get our alphabet
	alphabet := cryptoAlphabet()
	size := len(alphabet)

	if key > size {
		return nil, fmt.Errorf("invalid key: %d. Must be not greater than %d", key, size)
	}

	if key < 0 {
		return nil, fmt.Errorf("invalid key: %d. Can't be less than zero", key)
	}

	lookup := make(map[rune]int, size)

	// maps alphabet char on their indexes
	for i := range alphabet {
		lookup[alphabet[i]] = i
	}

	return &cryptographer{lookup: lookup, alphabet: alphabet, key: key}, nil
}

// NewEncoder returns instance of encoder that writes
// result to w
func (c *cryptographer) NewEncoder(w io.Writer) *Encoder {
	return &Encoder{c: c, w: w}
}

// NewKeyDecoder returns instance of Decoder that
// decode contents of r using known key
func (c *cryptographer) NewKeyDecoder(r io.Reader) *Decoder {
	dec := Decoder{c: c, r: r}
	dec.decf = dec.decode
	return &dec
}

// NewBruteForceDecoder returns instance of Decoder that
// decode contents of r using brute force method
func (c *cryptographer) NewBruteForceDecoder(r io.Reader) *Decoder {
	dec := Decoder{c: c, r: r}
	dec.decf = dec.bruteForce
	return &dec
}

// NewFreqAnalisysDecoder returns instance of Decoder that
// decode contents of r using frequency analysis method
func (c *cryptographer) NewFreqAnalisysDecoder(r io.Reader, helper io.Reader) *Decoder {
	dec := Decoder{c: c, r: r, hr: helper}
	dec.decf = dec.frequencyAnalysis
	return &dec
}

// Encode reads the contents of r, encoding it
// and writes to the stream
func (enc *Encoder) Encode(r io.Reader) error {

	// encoding logic
	f := func(char rune) rune {
		// if char is not in our alphabet
		// then encode it as skipRune
		pos, ok := enc.c.lookup[char]
		if !ok {
			return skipRune
		}

		// calculate the position after shift
		pos += enc.c.key
		if pos > len(enc.c.alphabet)-1 {
			pos = pos - len(enc.c.alphabet)
		}

		// encode it as shifted rune
		return enc.c.alphabet[pos]
	}

	// pass our logic to processor
	return process(r, enc.w, f)
}

// Decode reads the inner r and decode it contents to w
func (dec *Decoder) Decode(w io.Writer) error {
	return dec.decf(w)
}

// decode reads inner r and decode it contents to w
// using known key
func (dec *Decoder) decode(w io.Writer) error {

	f := func(char rune) rune {
		pos, ok := dec.c.lookup[char]
		if !ok {
			return skipRune
		}

		// backward shift
		pos -= dec.c.key
		if pos < 0 {
			pos = len(dec.c.alphabet) + pos
		}

		return dec.c.alphabet[pos]
	}

	// pass our logic to processor
	return process(dec.r, w, f)
}

// bruteForce reads inner r and tries to decode it contents to w
// sequentially selecting the keys
func (dec *Decoder) bruteForce(w io.Writer) error {

	b, err := io.ReadAll(dec.r)
	if err != nil {
		return err
	}
	match := false

	fmt.Printf("\nBrute-forcing ...\n")

	for ; dec.c.key < len(dec.c.alphabet); dec.c.key++ {

		fmt.Printf("trying key %d -> ", dec.c.key)

		// we run the text through a function that looks for patterns
		// function returns statistics over the text
		stat := dec.c.findCommonPatterns(b)

		// if text statistic exceeds the threshold
		// then the key is found
		pass := stat*100/len(b) >= 1

		printStatInfo(stat, len(b)/100, pass)

		if pass {
			match = true
			break
		}
	}

	if !match {
		fmt.Printf("Result: fail to brute-forcing\n")
		return nil
	}
	fmt.Println("Result: success. Decoding...")

	dec.r = bytes.NewReader(b)

	return dec.decode(w)
}

// frequencyAnalysis reads r and tries to decode it contents to w
// using the frequency analysis method
func (dec *Decoder) frequencyAnalysis(w io.Writer) error {

	fmt.Printf("\nDecoding by frequency analysis...\n")

	// read the helper
	b, err := io.ReadAll(dec.hr)
	if err != nil {
		return err
	}

	// find most frequent rune
	mfrDecrypted, err := dec.c.countMostFrequent(b)
	if err != nil {
		return err
	}

	// read the encoded
	b, err = io.ReadAll(dec.r)
	if err != nil {
		return err
	}

	// find most frequent rune
	mfrEncrypted, err := dec.c.countMostFrequent(b)
	if err != nil {
		return err
	}

	// get positions in alphabet
	posDec, posEnc := dec.c.lookup[mfrDecrypted], dec.c.lookup[mfrEncrypted]

	// calculate key
	if posDec <= posEnc {
		dec.c.key = posEnc - posDec
	} else {
		dec.c.key = len(dec.c.alphabet) + posEnc - posDec
	}

	fmt.Printf("trying possible key %d -> ", dec.c.key)

	/// we run the text through a function that looks for patterns
	// function returns statistics over the text
	stat := dec.c.findCommonPatterns(b)

	// if text statistic exceeds the threshold
	// then the key is found
	pass := stat*100/len(b) >= 1
	printStatInfo(stat, len(b)/100, pass)

	// if key is not found we try most frequent rune overall
	if !pass {
		fmt.Println("Avoiding helper, trying statistically most frequent character which is space")

		posDec, posEnc := dec.c.lookup[mostFrequentChar], dec.c.lookup[mfrEncrypted]

		if posDec <= posEnc {
			dec.c.key = posEnc - posDec
		} else {
			dec.c.key = len(dec.c.alphabet) + posEnc - posDec
		}

		fmt.Printf("trying possible key %d -> ", dec.c.key)
		stat := dec.c.findCommonPatterns(b)
		pass := stat*100/len(b) >= 1
		printStatInfo(stat, len(b)/100, pass)

		if !pass {
			return nil
		}
	}

	fmt.Println("Result: success. Decoding...")

	dec.r = bytes.NewReader(b)

	return dec.decode(w)
}

// countMostFrequent returns most frequent rune
// in provided text
func (c *cryptographer) countMostFrequent(b []byte) (rune, error) {

	fm := make(map[rune]int, len(c.alphabet))
	var mostFrequentChar rune

	for r, size, bs := skipRune, 0, b[:]; len(bs) > 0; bs = bs[size:] {

		r, size = utf8.DecodeRune(bs)

		if _, ok := c.lookup[r]; !ok {
			continue
		}

		fm[r]++
		i := fm[r]

		if i > fm[mostFrequentChar] {
			mostFrequentChar = r
		}
	}

	return mostFrequentChar, nil
}

// findCommonPatterns returns the statistics over the
// provided text (i.e how many times the pattern emerges in text)
func (c *cryptographer) findCommonPatterns(b []byte) int {
	stat := 0
	foundMode := 1
	// foundMode 1 == found [letter]
	// foundMode 2 == found [letter] -> [punctuation]
	// foundMode 3 ==  found [letter] -> [punctuation] -> [space]
	// foundMode 4 ==  success

runes:
	for r, size, bs := skipRune, 0, b[:]; len(bs) > 0; bs = bs[size:] {

		r, size = utf8.DecodeRune(bs)

		pos, ok := c.lookup[r]
		if !ok {
			continue
		}

		pos -= c.key
		if pos < 0 {
			pos = len(c.alphabet) + pos
		}

		char := c.alphabet[pos]

		switch char {
		case '-', '—':
			if foundMode == 2 {
				break runes
			}
		case ' ':
			if foundMode == 2 {
				foundMode++
			}
		case '.', ',', '!', '?', ':':
			if foundMode != 1 {
				break runes
			}
			foundMode++
		default:
			if foundMode == 3 {
				stat++
			}
			foundMode = 1
		}
	}
	return stat
}

func printStatInfo(stat, expected int, result bool) {
	fmt.Printf("found pattern matches %d; expected threshold %d", stat, expected)
	if result {
		fmt.Println(" -> Result: -> success")
	} else {
		fmt.Println(" -> Result: too few -> fail")

	}
}

// process reads runes from the source r and writes to
// the destination w, passing the data through
// the encryption/decryption function, which it receives as the third parameter
func process(r io.Reader, w io.Writer, f func(rune) rune) error {

	rw := bufio.NewReadWriter(
		bufio.NewReader(r),
		bufio.NewWriter(w),
	)

	for {
		char, _, err := rw.ReadRune()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		out := f(char)

		_, err = rw.WriteRune(out)
		if err != nil {
			return err
		}

	}

	rw.Flush()

	return nil
}
