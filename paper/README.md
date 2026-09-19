# Paper

| | |
|---|---|
| **English** | [`main.pdf`](main.pdf) · source [`main.tex`](main.tex) |
| **Portuguese** | [`main-pt.pdf`](main-pt.pdf) · source [`main-pt.tex`](main-pt.tex) |

*Cloud-Native Detection of Cyberattacks Against Satellite Ground Stations: An
Open, Labelled Testbed and Two Negative Results.* IEEE conference format, 10-11
pages, 24 references.

## Nothing in the manuscripts is typed by hand

`experiments.py` runs the whole evaluation and writes every number, table and
figure the sources consume:

```
data/results.json               full experimental record, incl. environment
data/macros.tex                 \exp... macros for main.tex
data/macros_pt.tex              the same values with comma decimals
data/table_{corpus,effectiveness,baseline,cost}.tex
data/table_*_pt.tex
figures/{ablation,roc,leadtime,phaseswap,baseline,alerts}.pdf
figures/*_pt.pdf                the same plots with translated labels
```

The two manuscripts therefore cannot disagree with each other or with the code:
they read the same results object. If a rule changes and the numbers move, both
PDFs move with them on the next build.

## Building

```bash
pip install -e ".[paper]"      # numpy, PyYAML, matplotlib
make -C paper                  # experiments -> figures/tables -> both PDFs
```

Needs a TeX distribution with `IEEEtran`, `pgf/tikz`, `booktabs` and, for the
Portuguese version, `babel-portuges`. On Debian/Ubuntu:

```bash
apt-get install --no-install-recommends \
  texlive-latex-base texlive-latex-recommended texlive-fonts-recommended \
  texlive-latex-extra texlive-publishers texlive-lang-portuguese latexmk
```

Individual steps: `make -C paper experiments`, `make -C paper en`,
`make -C paper pt`. The experiment sweep takes about ten seconds for the default
20 trials; `--seeds`/`--minutes` change the budget and `--langs en` skips the
Portuguese artefacts.

## Experiments

| | What it measures | Output |
|---|---|---|
| E0 | Corpus composition | `tab:corpus` |
| E1 | Per-scenario detection rate, recall, MTTD, precision | `tab:effectiveness` |
| E2 | Rules / model / both ablation | `fig:ablation` |
| E3 | Multivariate vs. best single channel (ROC, AUC) | `fig:roc` |
| E3b | Phase-swap probe: joint structure isolated from marginals | `fig:phaseswap` |
| E4 | Warning time ahead of the ICD limit check | `fig:leadtime` |
| E5 | Baseline-size sensitivity | `fig:baseline`, `tab:baseline` |
| E6 | Single-core throughput and model size | `tab:cost` |
| E7 | Alert volume by severity and hour | `fig:alerts` |

## Before submitting anywhere

Replace the author block in both `.tex` files — it currently carries a
placeholder name and no affiliation.

## Figure conventions

Figures use a colourblind-safe palette validated against CVD and normal-vision
separation floors, redundant encodings (dash patterns, markers, hatching) so
they survive grayscale printing, direct value labels where a fill sits below
3:1 contrast on white, and one y-axis per panel — small multiples rather than a
second scale.
