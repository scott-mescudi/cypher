# Detect the operating system
OS := $(shell uname -s)

# Default target
all: build

# Rule to build the Go programs based on the OS
build:
ifeq ($(OS),Linux)
	@echo "Building for Linux..."
	go build -o encrypt encrypt.go
	go build -o decrypt decrypt.go
else ifeq ($(OS),Darwin)
	@echo "Building for macOS..."
	go build -o encrypt encrypt.go
	go build -o decrypt decrypt.go
else ifeq ($(OS),Windows_NT)
	@echo "Building for Windows..."
	go build -o encrypt encrypt.go
	go build -o decrypt decrypt.go
else
	@echo "Unsupported OS: $(OS)"
endif

# Clean up the binaries
clean:
	@echo "Cleaning up..."
	rm -f encrypt decrypt

.PHONY: all build clean
