PROGS = cli srv

all: $(PROGS) $(DOC)

srv: srv.c
cli: cli.c

.PHONY: clean

clean:
	rm -f *.o socket $(PROGS)
