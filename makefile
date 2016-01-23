CFLAGS += -g -O0

all: HohhaDynamicXOR HohhaHarness

HohhaDynamicXOR: HohhaDynamicXOR.o

HohhaDynamicXOR.o: CFLAGS += -Wno-implicit-int

HohhaHarness: HohhaHarness.o HohhaDynamicXOR-NOMAIN.o

HohhaDynamicXOR-NOMAIN.o: HohhaDynamicXOR.o
	strip -N main -o $@ $<

clean:
	rm -fv HohhaDynamicXOR HohhaHarness *.o
