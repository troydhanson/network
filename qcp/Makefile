CFLAGS=-g
EXES = qcp qcps
all: $(EXES) 

.PHONY: clean

install: $(EXES)
	cp $(EXES) /usr/local/bin

clean:
	rm -f *.o $(EXES)
