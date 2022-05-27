package caesarCypher

import "fmt"

type CaesarCypherController struct{}

func NewCaesarCypherController() CaesarCypherController {
	return CaesarCypherController{}
}

func (c CaesarCypherController) Start() int {

	for {

		printUsage(mainMode)

		in, err := scanInput()
		if err != nil {
			return out(err)
		}

		err = handleInput(in, handleInputMain)
		if err != nil {
			if err.Error() == exitMode {
				fmt.Println("Goodbye")
				break
			}
			return out(err)
		}
	}

	return 0
}

func out(err error) int {
	fmt.Println(err)
	fmt.Println("type any key to terminate program: ")
	_, _ = scanInput()
	return 1
}
