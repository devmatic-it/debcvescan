###############################################################################
# Makefile Go Projects
#
# Author F. Bator
###############################################################################

TARGET= ./cmd/debcvescan
GOBASE=$(shell pwd)
GOPATH=$(GOBASE)
GOBIN=$(GOBASE)/build
GOFILES=$(wildcard *.go)
PKG := "github.com/devmatic-it/debcvescan"
PKG_LIST := $(shell go list ${PKG}/... | grep -v /vendor/)
GO_FILES := $(shell find . -name '*.go' | grep -v /vendor/ | grep -v _test.go)

all:  compile

compile: get install test-coverage

get:
	@echo "Downloading dependencies..."	
	GOBIN=$(GOBIN) go get $(TARGET)


install:
	@echo "Building binary..."
	GOBIN=$(GOBIN) go install $(TARGET)
	
test-coverage:
	@go test -short -coverprofile cover.out -covermode=atomic ${PKG_LIST} 
	@cat cover.out >> coverage.txt

clean:
	@echo "Cleanup dependencies..."	
	rm -Rf ./src/github.com 
	rm -Rf ./src/golang.org
	rm -Rf ./src/gopkg.in	
