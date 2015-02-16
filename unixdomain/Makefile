CFLAGS = -g
ASCIIDOC=/usr/bin/asciidoc
DOC = Unix_domain_sockets.html
PROGS = cli srv

all: $(PROGS) $(DOC)

srv: srv.c
cli: cli.c

Unix_domain_sockets.html: Unix_domain_sockets.txt
	if [ -x $(ASCIIDOC) ]; then $(ASCIIDOC) $<; fi

.PHONY: clean

clean:
	rm -f *.o socket $(PROGS)
