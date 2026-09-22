# Cover letter

> Fill in the bracketed fields, then paste into the submission system's cover
> letter box (or export to PDF). Everything else is already accurate for this
> manuscript. Delete the two "not applicable" paragraphs only if they are
> genuinely not applicable — the journal asks for them explicitly.

---

**To:** The Editor-in-Chief, [journal name]

**Manuscript:** *Cloud-Native Detection of Cyberattacks Against Satellite Ground
Stations: An Open, Labelled Testbed and Two Negative Results*

**Author:** [full name], [affiliation], [e-mail]

Dear Editor,

Please consider the attached manuscript for publication in [journal name].

**Contribution.** The ground segment of a satellite mission is an ordinary cloud
workload, and an adversary who reaches its commanding path controls the vehicle
without touching a radio. Published satellite-security research concentrates on
the spacecraft and the radio link, and there is no open, labelled corpus against
which ground-segment detection can be measured. We contribute three things: an
open corpus generator (a simulated ground station emitting four correlated
planes of evidence, with five adversary-emulation scenarios that label every
event they inject); a cloud-native detection pipeline of 21 stateful rules plus
an unsupervised telemetry baseline; and an evaluation over 20 independent trials
that reports not only what works but two results that contradict our own design
rationale.

**Why we believe it merits review.** The paper's most useful findings are
negative and, to our knowledge, not previously reported. First, on our
behavioural attack the multivariate baseline does not outperform a
well-calibrated per-channel detector, and we say so rather than reporting only
the favourable comparison. Second, a controlled probe that preserves every
marginal distribution while destroying the joint structure — replaying
housekeeping frames from half an orbit earlier — is invisible to both
detectors, scoring *below chance*: the attack drives the anomaly score down
while a fault progresses. This is a structural property of any baseline fitted
over a full orbit, applies to considerably more sophisticated detectors than
ours unless they condition on orbit phase, and the probe that exposes it is a
few lines of code that any telemetry detector can be subjected to. We also
report a sharp operational threshold that a detector reporting only area under
the curve would miss entirely.

**Prior publication.** This manuscript is not an extension of a conference
paper. It has not been published, in whole or in part, elsewhere, and it is not
under consideration by any other journal.

**Prior submission history.** This manuscript has not been previously submitted
to or rejected by another journal. *[If that changes, this paragraph must state
the journal, summarise the changes made, and the previous decision letter must
be attached.]*

**Use of generative AI.** In accordance with IEEE policy on
artificial-intelligence-generated text, we declare that a large language model
(Anthropic Claude, via the Claude Code command-line interface) was used
substantially in preparing this work: it assisted in writing the simulator, the
detection engine, the infrastructure code and the experiment harness, and in
drafting the manuscript. All experimental results were produced by executing the
released code. The author reviewed and verified the content and takes full
responsibility for it. This declaration also appears in the Acknowledgments.

**Reproducibility.** All code, the experiment harness, the generated data and
the manuscript sources are public at
<https://github.com/rikosoo/Cloud-Native-Detection-of-Cyberattacks-Against-Satellite-Ground-Stations>.
Running `python paper/experiments.py` regenerates every number, table and figure
in the manuscript. The evaluation completes in under ten seconds on a laptop and
requires no cloud account.

**Access model.** We request the traditional (non-open-access) publication model.

**Suggested reviewers.** [3–5 names with affiliations and e-mail addresses, none
a recent co-author.]

**Conflicts of interest.** [None / list them.]

Thank you for your consideration.

Sincerely,
[full name]
