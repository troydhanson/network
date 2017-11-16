ASCIIDOC=/usr/bin/asciidoc
DOC = Unix_domain_sockets.html

all: $(DOC)

Unix_domain_sockets.html: Unix_domain_sockets.txt
	if [ -x $(ASCIIDOC) ]; then $(ASCIIDOC) $<; fi

