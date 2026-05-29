CUDA_HOME ?= /usr/local/cuda
NVCC = $(CUDA_HOME)/bin/nvcc
CFLAGS = -O3 -arch=native -std=c++17 -lineinfo
TARGET = engine
INCS = -I/home/ubuntu/vaultwatch -I/home/ubuntu/seedhammer

all: $(TARGET)

$(TARGET): main.cu
	$(NVCC) $(CFLAGS) main.cu -o $(TARGET) $(INCS)

clean:
	rm -f $(TARGET) *.o found.txt

.PHONY: all clean
