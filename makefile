uml:
	@pyreverse m??.py -o svg
	@rm classes.svg
	@sed -i "s/Times,serif/Inconsolata, DejaVu Sans Mono, monospace/g" packages.svg

umlpdf:
	@pyreverse m??.py
	@rm classes.dot
	@dot2tex packages.dot -f tikz > packages.tex
	@sed -i "1s/article/standalone/" packages.tex
	-@pdflatex packages.tex
	@rm -v packages.{aux,dot,log,tex}

.PHONY: test
test:
	@python -W ignore -m unittest

.PHONY: lint
lint:
	@pylint -f colorized m??.py

