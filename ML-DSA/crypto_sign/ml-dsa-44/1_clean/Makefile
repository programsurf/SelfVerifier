# This Makefile can be used with GNU Make or BSD Make

CC ?= gcc

CFLAGS=  -Os -Wall -Wextra -Wpedantic -Werror -Wmissing-prototypes -Wredundant-decls -march=native  -I../../../common -fstack-usage $(EXTRAFLAGS)


LIB=libml-dsa-44_clean.a
HEADERS=api.h ntt.h packing.h params.h poly.h polyvec.h reduce.h rounding.h sign.h symmetric.h 
OBJECTS=ntt.o packing.o poly.o polyvec.o reduce.o rounding.o sign.o symmetric-shake.o 

all: $(LIB) test_mldsa44 benchmark_mldsa44 valgrind_test_mldsa44 mldsa_cli 

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) -r $@ $(OBJECTS)

clean:
	$(RM) $(OBJECTS)
	$(RM) $(LIB)
	$(RM) test_mldsa44 benchmark_mldsa44 valgrind_test_mldsa44
	$(RM) perf_keygen perf_sign perf_verify
	$(RM) mldsa_cli

test: test_mldsa44
	./test_mldsa44

test_mldsa44: test_mldsa44.c $(LIB)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -o test_mldsa44 test_mldsa44.c $(LIB) ../../../common/fips202.c

benchmark_mldsa44: benchmark_mldsa44.c $(LIB)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -o benchmark_mldsa44 benchmark_mldsa44.c $(LIB) ../../../common/randombytes.c ../../../common/fips202.c

valgrind_test_mldsa44: valgrind_test_mldsa44.c $(LIB)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -o valgrind_test_mldsa44 valgrind_test_mldsa44.c $(LIB) ../../../common/randombytes.c ../../../common/fips202.c

perf_keygen: perf_keygen.c $(LIB)
	$(CC) $(CFLAGS) -o perf_keygen perf_keygen.c $(LIB) ../../../common/randombytes.c ../../../common/fips202.c

perf_sign: perf_sign.c $(LIB)
	$(CC) $(CFLAGS) -o perf_sign perf_sign.c $(LIB) ../../../common/randombytes.c ../../../common/fips202.c

perf_verify: perf_verify.c $(LIB)
	$(CC) $(CFLAGS) -o perf_verify perf_verify.c $(LIB) ../../../common/randombytes.c ../../../common/fips202.c

mldsa_cli: mldsa_cli.c $(LIB)
	$(CC) $(CFLAGS) -Wno-missing-prototypes -o mldsa_cli mldsa_cli.c $(LIB) ../../../common/randombytes.c ../../../common/fips202.c
