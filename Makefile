MAKEFLAGS = --warn-undefined-variables

SRC = m??.py
TEST = test.py

export PIP_DISABLE_PIP_VERSION_CHECK=1

venv: requirements.txt requirements_dev.txt
	@python3 -m venv $@ --prompt $@::crypto
	@source $@/bin/activate && pip install -r $< -r requirements_dev.txt
	@echo "enter virtual environment: source $@/bin/activate"

.PHONY: outdated
outdated: venv
	@source $</bin/activate && pip list --$@

packages.svg: $(SRC)
	@pyreverse $(SRC) -o svg
	@rm classes.svg
	@sed -i "s/Times,serif/Inconsolata, DejaVu Sans Mono, monospace/g" $@

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
	@python -m unittest --buffer

coverage: $(SRC) $(TEST)
	@coverage run --branch --concurrency=thread --omit=venv/* test.py
	@coverage report -m
	@coverage html -d ./coverage
	@coverage erase

.PHONY: lint
lint:
	@pylint -f colorized $(SRC) $(TEST)

.PHONY: flake8
flake8:
	@flake8 $(SRC) $(TEST)

.PHONY: typecheck
typecheck:
	@mypy $(SRC) $(TEST)

.PHONY: clean
clean:
	@$(RM) -r coverage/
	@$(RM) -r .mypy_cache/
	@$(RM) -r __pycache__/
	@$(RM) tags
