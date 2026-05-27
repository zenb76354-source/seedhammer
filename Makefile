CUDA_HOME ?= /usr/local/cuda
CC = $(CUDA_HOME)/bin/nvcc
CFLAGS = -O3 -arch=native -std=c++17 -lineinfo -Xcompiler -fopenmp
TARGET = seedhammer
OBJS = main.o hypothesis_gpu.o

all: $(TARGET)

main.o: main.cu hypothesis_gpu.cu
	$(CC) $(CFLAGS) -c main.cu -o main.o

hypothesis_gpu.o: hypothesis_gpu.cu
	$(CC) $(CFLAGS) -c hypothesis_gpu.cu -o hypothesis_gpu.o

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(TARGET) -lssl -lcrypto -lpthread

# Mode-specific targets (convenience aliases)
run-M: $(TARGET)
	./$(TARGET) M --ts-start 1288834970 --ts-end 1288924970 --output keys_m.bin

run-R: $(TARGET)
	./$(TARGET) R --ts-start 1288834970 --ts-end 1288924970 --output keys_r.bin

run-C: $(TARGET)
	./$(TARGET) C --ts-start 1288834970 --ts-end 1288924970 --output keys_c.bin

run-J: $(TARGET)
	./$(TARGET) J --seed-start 0 --seed-end 4294967295 --output keys_j.bin

run-K: $(TARGET)
	./$(TARGET) K --prefix L --output keys_k.bin

run-CQ: $(TARGET)
	./$(TARGET) CQ --dict data/chinese_brainwallet.txt --output keys_cq.bin

run-LC: $(TARGET)
	./$(TARGET) LC --seed-range 0,86400 --output keys_lc.bin

run-W: $(TARGET)
	./$(TARGET) W --ts-start 1293840000 --ts-end 1356998400 --output keys_w.bin

run-B: $(TARGET)
	./$(TARGET) B --username-list data/usernames.txt --password-list data/passwords_top100.txt --output keys_b.bin

run-ALL: $(TARGET)
	./$(TARGET) ALL --ts-start 1262304000 --ts-end 1356998400 --output keys_all.bin --progress

clean:
	rm -f $(TARGET) *.o *.bin *.txt

.PHONY: all clean run-M run-R run-C run-J run-K run-CQ run-LC run-W run-B run-ALL