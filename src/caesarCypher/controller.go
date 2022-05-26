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
			fmt.Println(err)
			fmt.Println("type any key to terminate program: ")
			return 1
		}

		err = handleInput(in, handleInputMain)
		if err != nil {
			if err.Error() == exitMode {
				fmt.Println("Goodbye")
				break
			}
			fmt.Println(err)
			fmt.Println("type any key to terminate program: ")
			_, _ = scanInput()
			return 1
		}
	}

	return 0
}
