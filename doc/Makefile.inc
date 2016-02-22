.adoc.html:
	asciidoc -a data-uri -b html5  -a icons -a toc2  -a max-width=55em --out-file=$@ $<
