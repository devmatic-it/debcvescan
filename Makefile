###############################################################################
# Makefile Go Projects
#
# Author F. Bator
###############################################################################

TARGET= ./cmd/debcvescan
GOBASE=$(shell pwd)
GOPATH=$(GOBASE)
GOBIN=$(GOBASE)/bin
GOFILES=$(wildcard *.go)

all:  compile

compile: get install

get:
	@echo "Downloading dependencies..."	
	GOBIN=$(GOBIN) go get $(TARGET)


install:
	@echo "Building binary..."
	GOBIN=$(GOBIN) go install $(TARGET)
	
clean:
	@echo "Cleanup dependencies..."	
	rm -Rf ./src/github.com 
	rm -Rf ./src/golang.org
	rm -Rf ./src/gopkg.in	
