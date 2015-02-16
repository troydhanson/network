HTML=$(patsubst %.txt,%.html,$(wildcard *.txt))
all: warning $(HTML)

warning:
	@if [ -z "`type -t asciidoc`" ]; then \
	echo "this Makefile is for building the documentation"; \
	false; else true; fi

# when each target of a multi-target rule has its own prereq 
# we use a static pattern rule. 
$(HTML): %.html: %.txt
	asciidoc $<

TMP=/tmp/network-scripts-gh-pages
stage:
	mkdir -p ${TMP}
	rm -rif ${TMP}/*
	find . -name '*.html' -exec cp -i {} ${TMP} \;

