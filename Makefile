###############################################################################
# Makefile Go Projects
#
# Author F. Bator
###############################################################################

GOBASE=$(shell pwd)
GOBIN=$(GOBASE)/dist
PKG := "github.com/devmatic-it/debcvescan"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)

all:  compile

compile: get build test-coverage security

get:
	@echo "Downloading dependencies..."	
	GOBIN=$(GOBIN) go get github.com/securego/gosec/v2/cmd/gosec
	GOBIN=$(GOBIN) go get

security:
	@echo "Gosec security scan..."
	dist/gosec -fmt html -out gosec_report.html  ./...	

build:
	@echo "Building binary..."
	GOBIN=$(GOBIN) go build -o dist/debcvescan
	
test-coverage:
	@go test -short -coverprofile cover.out -covermode=atomic ${PKG_LIST} 
	@cat cover.out >> coverage.txt

clean:
	@echo "Cleanup dependencies..."	
	rm -Rf ./src/github.com 
	rm -Rf ./src/golang.org
	rm -Rf ./src/gopkg.in
	rm -Rf ./dist/*
	rm cover.out coverage.txt gosec_report.html
