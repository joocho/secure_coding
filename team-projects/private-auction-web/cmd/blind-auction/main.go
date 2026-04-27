package main

import (
	"fmt"
	"os"

	"blind-auction-go/internal/tui"
)

func main() {
	if err := tui.Run(); err != nil {
		fmt.Printf("실행 오류: %v\n", err)
		os.Exit(1)
	}
}
