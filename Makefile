MAKEFLAGS = --warn-undefined-variables

SRC = m??.py
TEST = test.py

export PIP_DISABLE_PIP_VERSION_CHECK=1

venv: requirements.txt requirements_dev.txt
	@python3 -m venv $@ --prompt $@::crypto
	@source $@/bin/activate && pip install -r $< -r requirements_dev.txt
	@echo "enter virtual environment: source $@/bin/activate"

packages.svg: $(SRC)
	@pyreverse $(SRC) -o svg
	@rm classes.svg
	@sed -i "s/Times,serif/Inconsolata,monospace/g" $@

tags: $(SRC) $(TEST)
	@ctags --languages=python $^

.PHONY: test
test:
	@python -m unittest --buffer

coverage: $(SRC) $(TEST)
	@coverage run $(TEST)
	@coverage report
	@coverage html -d ./$@
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
