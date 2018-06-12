SRC = m??.py
TEST = test.py

.PHONY: uml
uml: packages.svg

packages.svg: $(SRC)
	@pyreverse $(SRC) -o svg
	@rm classes.svg
	@sed -i "s/Times,serif/Inconsolata, DejaVu Sans Mono, monospace/g" packages.svg

.PHONY: umlpdf
umlpdf: packages.pdf

packages.pdf: $(SRC)
	@pyreverse $(SRC)
	@rm classes.dot
	@dot2tex packages.dot -f tikz > packages.tex
	@sed -i "1s/article/standalone/" packages.tex
	-@pdflatex packages.tex
	@rm -v packages.{aux,dot,log,tex}

tags: $(SRC) $(TEST)
	@ctags --languages=python --python-kinds=-i $(SRC) $(TEST)

.PHONY: test
test:
	@python -W ignore -m unittest

coverage: $(SRC) $(TEST)
	@coverage run --source=. --branch --concurrency=thread test.py
	@coverage report -m
	@coverage html -d ./coverage
	@coverage erase

.PHONY: lint
lint:
	@pylint -f colorized $(SRC) $(TEST)

