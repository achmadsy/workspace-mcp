package main

import "fmt"

// Greet returns a friendly greeting message.
func Greet(name string) string {
	return fmt.Sprintf("Hello, %s!", name)
}

func main() {
	fmt.Println(Greet("workspace"))
}
