package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"blind-auction-go/internal/auction"
	"blind-auction-go/internal/db"
	"blind-auction-go/internal/security"
)

func main() {
	auctionID := flag.String("id", "", "ID of the auction to reveal")
	dbPath := flag.String("db", "db/blind_auction.db", "Path to SQLite DB")
	flag.Parse()

	if *auctionID == "" {
		fmt.Println("Usage: reveal -id <auction_uuid>")
		os.Exit(1)
	}

	// 1. DB 초기화
	database, err := db.InitDB(*dbPath)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}
	defer database.Close()

	// 2. 서비스 초기화
	audit := security.NewAuditLogger(database)
	// Authenticator는 Reveal 과정에서는 직접 필요 없으므로 nil 전달 (또는 Mock)
	auctionSvc := auction.NewService(database, audit)

	// 3. 결과 공개 실행
	fmt.Printf("Revealing results for auction: %s...\n", *auctionID)
	err = auctionSvc.RevealAuctionResults(context.Background(), *auctionID)
	if err != nil {
		log.Fatalf("Reveal failed: %v", err)
	}

	fmt.Println("Successfully revealed all bids and updated auction status to REVEALED.")
}
