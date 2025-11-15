# The E2E-VIV Threat Model

**February 2026**

## Background

The threat model we have developed for this system is based upon all of the threat models we are aware of that have been published about remote/Internet voting systems.

There is a surprisingly small amount of literature on this topic.  We looked for threat models from existing vendors, in academic literature, and in critiques of past voting systems.

None of the mainstream existing vendors of supervised or Internet voting systems publishes a threat model.  Some publish high-level security white papers, but none publish real threat models.

Researchers that have examined these systems have had to reverse engineer informal threat models as a part of their work, such as in Specter and Halderman's review of the Democracy Live platform [SpecterHalderman21], Specter, Koppel, and Weitzner's analysis of the Voatz platform [SpecterKoppelWeitzner20], Halderman et al's analysis of the Estonian system [SpringallEtAl14], and Park et al.'s examination of Internet voting systems in the general [ParkEtAl21].  There are many other examples of such analyses [CulnaneEtAl19, HaldermanTeague15, HainesEtAl22, TeagueWen11].

Our partner and subcontractor on this project, [Sequent](https://sequentech.io/), is the only company that has published a (partial, informal) threat model for their system.

## Threat Modeling

A threat model consists of:

 1. a characterization of the *adversaries* of a system, including their knowledge, capabilities, and goals;
 2. *attacks* that the adversaries wish to carry out against the system;
 3. *weaknesses* in the system, whatever their source (hardware and software dependencies, technological or design choices choices, etc.); and
 4. the *mitigations* put in place within the system in order to stop or blunt adversaries from achieving their goals; and
 5. an explicit statement of the attacks and weaknesses that are *unmitigated*.

Threat models are built through domain experience and security wisdom.  There is no magic methodology to guarantee that a threat model is complete or "good."

There are a number of best practices that can help practitioners construct high-quality threat models.  Stakeholders must be consulted to understand who and what they are worried about and why.  One must be intimate with the technological weaknesses inherit in any choice of hardware, firmware, and software.  Moreover, there are a host of architectural and design weaknesses to avoid.

This threat model is for an *E2E-V cryptographic protocol* and its implementation.  It is **not** a complete threat model for a deployable Internet voting system.  In particular, there are a number of threats that a cryptographic protocol **cannot** mitigate.  Those threats can only be stopped or blunted by *systems mitigations*, usually related to how one designs, builds, and deploys distributed systems at scale.

We are up-front about the attacks that we cannot mitigate.  Some of these attacks, such as large-scale compromise of voters' devices, cannot be mitigated with today's technology, and it is an open research question as to whether they can ever be mitigated.

The capabilities versus security trade-off inherent in any system asks the question: "Are these new capabilities worth the risks inherent in the unmitigated weaknesses or attacks?"  In the context of the end-to-end verifiable Internet voting system that is the focus of this R&D, the question that election officials must ask is similar: "Are the new capabilities in this Internet voting systems worth the risks inherent in its adoption, and is this capabilities-security trade-off better or worse than my jurisdiction's current early voting scheme?"

## Summary of the Threat Model

Our semi-formal threat model, found in [src](src), is written in Python, using a custom encoding that we developed for this project.

It is certainly possible for individuals to review the Python encoding directly. However, in order to facilitate review by any interested party, and to examine the threat model from various points of view as well as reason about the relationships among elements of the model, we have also built some tools to visualize the data in multiple ways.

Historically, in order to best understand and review complex threat models, authorities typically want them written down in a structured, static fashion (e.g., as Word or PDF documents). Recently, it has been recognized that an interactive view of complex threat models is valuable, as it permits a cybersecurity reviewer to navigate the threat model dynamically, asking questions, finding answers, and critiquing what is found. Therefore, we have built support for both of these modes of viewing and interacting with the threat model.

The static view of the model is written [in LaTeX](threat-model.tex) and its dynamic components, which come from updates to the Python threat model, are automatically rendered into the document.  These dynamic components are generated with the `latex` target in the provided `Makefile`, and the `pdf` target builds the PDF version of the threat model.

Two dynamic views of the model ara available through a web browser. One permits the user to "surf" the model interactively in a text-based fashion, and is implemented using a local HTTP server; the other permits the user to interact with a graph representation of the threat model, and is implemented as a static HTML file.

In order to run (and stop) the threat model server, use the `server` and `stop` targets in the `Makefile`. In order to generate the threat model graph HTML file, use the `graph` target in the `Makefile`. For more details about the underlying Python package and its supported commands, see [README_PYTHON.md](README_PYTHON.md).

[GranataEtAl24] Daniele Granata, Massimiliano Rak, Paolo Palmiero, and Adele Pastena.  [A Methodology for Vulnerability Assessment and Threat Modelling of an e-Voting Platform Based on Ethereum Blockchain](https://ieeexplore.ieee.org/stamp/stamp.jsp?arnumber=10750196).  IEEE Access, Volume 12, 2024.

[ParkEtAl21] Sunoo Park, Michael Specter, Neha Narula, and Ronald L Rivest.  [Going from Bad to Worse: From Internet Voting to Blockchain Voting](https://academic.oup.com/cybersecurity/article/7/1/tyaa025/6137886).  Journal of Cybersecurity, Volume 7, Issue 1, 2021.

[SpecterHalderman21] Michael Specter and J. Alex Halderman.  [Security Analysis of the Democracy Live Online Voting System](https://www.usenix.org/conference/usenixsecurity21/presentation/specter-security).  USENIX Security 2021.

[SpecterKoppelWeitzner20] Michael A. Specter, James Koppel, and Daniel Weitzner. [The Ballot is Busted Before the Blockchain: A Security Analysis of Voatz, the First Internet Voting Application Used in U.S. Federal Elections](https://www.usenix.org/conference/usenixsecurity20/presentation/specter).  USENIX Security 2020.

[SpringallEtAl14] Drew Springall, Travis Finkenauer, Zakir Durumeric, Jason Kitcat, Harri Hursti, Margaret MacAlpine, and J. Alex Halderman.  [Security Analysis of the Estonian Internet Voting System](https://dl.acm.org/doi/10.1145/2660267.2660315).  CCS 2014.

[TeagueWen11]

[CulnaneEtAl19]

[HaldermanTeague15]

[HainesEtAl22]
