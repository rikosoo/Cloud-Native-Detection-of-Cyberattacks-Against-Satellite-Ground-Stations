# IEEE Transactions submission package

Everything here is formatted to the rules you supplied: double column, 10pt,
under the page limit, a 250-word single-paragraph abstract with no citations or
equations, no author biographies, and a generative-AI declaration.

`make check` verifies all of that mechanically.

---

## ⚠️ Read this before submitting

**The rules you gave me are IEEE Transactions on Medical Imaging's, and this
paper is out of scope for that journal.** TMI publishes methodological
contributions in medical image processing and analysis — reconstruction models,
segmentation networks, image-based diagnosis. This paper is about intrusion
detection on satellite ground-station telemetry and cloud audit logs. There is
no medical imaging in it.

A manuscript outside a journal's scope is desk-rejected by the editor before
review, regardless of how well it is formatted. Formatting is not the binding
constraint here; venue choice is. I formatted it anyway, because the rules you
listed are near-universal across IEEE Transactions, so this package transfers
to an in-scope journal with a change of title block.

**In-scope IEEE venues to consider instead** (verify each one's current page and
fee policy on its own author page — I have not):

| Venue | Why it fits |
|---|---|
| IEEE Trans. on Aerospace and Electronic Systems | Space and aerospace systems; the spacecraft/ground-segment half lands squarely here |
| IEEE Trans. on Information Forensics and Security | Intrusion detection and security measurement |
| IEEE Trans. on Dependable and Secure Computing | Security and dependability of systems |
| IEEE Systems Journal | Systems-level engineering with a security focus |

Avoid IEEE Access for your stated goal: it is open-access only, so there is
always an article processing charge.

One more honest caveat about fit, independent of venue. This paper's evaluation
is entirely on a **synthetic corpus**, and its headline findings are
**negative**. Both are defensible — the limitations section says so plainly, and
negative results are the contribution — but reviewers at a top-tier venue will
push hard on the synthetic-data threat to validity. A venue that values
artefacts and reproducibility will receive it better than one that expects
operational data.

---

## Publishing for free

Under the traditional (non-open-access) model there is no charge up to
**8 published pages**. Beyond that, roughly **$250 per extra page**. Open access
costs roughly **$2,800** regardless of length.

| | |
|---|---|
| Submission limit | 10 pages — over this is rejected without review |
| This manuscript | **8 pages**, of which page 8 is only the reference list |
| Free ceiling | 8 published pages under the traditional model |
| Margin | **None.** See below. |

**The risk is real and you should plan for it.** The free allowance counts
*published* pages after IEEE typesetting, not pages of this preprint. The
published two-column format is not identical to the `IEEEtran` author template,
so this could typeset to 7, 8, or 9 pages. At 9 pages you owe about $250.

If you need to guarantee no charge, the two cheapest cuts — in the order I would
make them, each costing the least science per line saved — are:

1. **Fig. 1**, the pipeline diagram (~0.45 column). The text describes the same
   flow, and the diagram survives in the extended version.
2. **Section 7.1**, "Rules and models do different jobs" (~0.6 column). The
   Conclusion already states the claim.

Together those should pull it under 7 pages with margin. I stopped trimming at
8 because going further starts removing content that carries the argument, and
that is your call rather than mine.

The trimming already applied, relative to the extended version in
[`../paper/`](../paper/): the conference-format paper is 10 pages with six
figures and five tables; this one is 8 pages with three figures and three
tables. Dropped here and kept there: the ROC curve (two indistinguishable
curves whose message is two numbers in the text), the lead-time histogram (one
sentence of text), the alert-volume chart, the deployment-mapping table, the
baseline-sensitivity table and the cost table. Cite the repository for the
extended version if a reviewer asks for them.

---

## Files

| File | What it is |
|---|---|
| `main.tex`, `main.pdf` | The submission manuscript |
| `refs.bib` | Bibliography, 24 entries |
| `cover-letter.md` | Cover letter template, already filled in except for your details |
| `check_compliance.py` | Mechanical check of every formatting rule |
| `data/`, `figures/` | Symlinks to `../paper/` — one source of truth |

Numbers, tables and figures come from `../paper/experiments.py`, the same
harness that drives the extended version. Nothing in `main.tex` is a
hand-typed number, so the two versions cannot disagree.

## Building

```bash
make -C IEEE            # build, then check compliance
make -C IEEE check      # check only
make -C IEEE package    # flatten symlinks into package/ for upload
```

`package/` contains the `.tex`, `.bbl`, `.bib`, the three figures actually
referenced, and the cover letter — zip it and upload.

Requires the same TeX packages as `../paper` (`IEEEtran`, `pgf/tikz`,
`booktabs`); the Portuguese language support is not needed here.

## Compliance status

```
[PASS] page limit (submission)         8 pages, limit 10
[PASS] page limit (no fee)             8 pages, 8 free
[PASS] abstract length                 244 words, limit 250
[PASS] abstract is one paragraph
[PASS] abstract has no citations
[PASS] abstract has no equations
[PASS] abstract abbreviations defined
[PASS] no author biographies
[PASS] double column, 10pt journal
[PASS] generative AI use declared
```

## Before you submit

1. **Replace the author block** in `main.tex` — it reads `Henrique [Surname]`
   with no affiliation or e-mail.
2. **Fill in `cover-letter.md`** — bracketed fields, and suggested reviewers.
3. **Pick a journal that covers this topic** (see the warning above) and adjust
   the `\markboth` running head.
4. **Re-run `make check`** after any edit.

## A note on the AI declaration

`main.tex` carries an explicit declaration that a large language model was used
substantially in producing the code and the manuscript, and `cover-letter.md`
repeats it. This is accurate and IEEE policy requires it. Do not remove it. If
you rewrite the manuscript substantially yourself, narrow the declaration to
what remains true rather than deleting it.

## Portuguese version

There is no Portuguese version in this folder: a journal submission is in
English. The Portuguese reading copy of the full paper is
[`../paper/main-pt.pdf`](../paper/main-pt.pdf), in the extended 11-page format.
Ask if you want a Portuguese translation trimmed to these same rules — the
harness already generates Portuguese figures and tables.
