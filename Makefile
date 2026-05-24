CC = nvcc
CFLAGS = -O2 -arch=sm_100 -std=c++17
TARGET = seedhammer
OBJS = main.o

all: $(TARGET)

main.o: main.cu
	$(CC) $(CFLAGS) -c main.cu -o main.o

$(TARGET): main.o
	$(CC) $(CFLAGS) main.o -o $(TARGET)

clean:
	rm -f $(TARGET) *.o *.bin

.PHONY: all clean
