TARGET := problem2
TARGET_BPF := eBPF.o

GO_SRC := main.go
BPF_SRC := eBPF.bpf.c

ARCH := $(shell uname -m)

.PHONY: all
all: $(TARGET) $(TARGET_BPF)

$(TARGET): $(GO_SRC) go.mod go.sum
	go build -o $(TARGET)

$(TARGET_BPF): $(BPF_SRC)
	clang -O2 -g -c -target bpf \
		-I/usr/include -I/usr/include/$(ARCH)-linux-gnu \
		-o $@ $<

.PHONY: vet
vet:
	go vet ./...

.PHONY: clean
clean:
	go clean
	rm -f $(TARGET) $(TARGET_BPF)