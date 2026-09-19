# Build the manuscript. Run the experiments first: they generate every figure,
# every table and every \exp... macro the sources depend on.
PYTHON ?= python3
MAIN   := main
PT     := main-pt

.PHONY: all experiments en pt clean

all: experiments en pt

experiments:
	$(PYTHON) experiments.py $(EXPFLAGS)

en:
	latexmk -pdf -interaction=nonstopmode -halt-on-error $(MAIN).tex

pt:
	latexmk -pdf -interaction=nonstopmode -halt-on-error $(PT).tex

clean:
	latexmk -C $(MAIN).tex $(PT).tex
	rm -f *.bbl *.blg *.run.xml
