VPATH=$(top_builddir)/doc/images

.msc.svg:
	mscgen -T svg -i $^ -o $@

.gv.svg:
	dot -T svg $^ -o $@

.adoc.html:
	asciidoc $(ASCIIDOC_FLAGS) --out-file=$@ $<

ASCIIDOC_FLAGS =-a data-uri -b html5  -a icons -a toc2  -a max-width=55em
