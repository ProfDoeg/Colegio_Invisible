% colegio.cls — Colegio Invisible / Quipu Protocol document class
%
% A Tufte-inspired class for inscribed essays and books in the Colegio
% Invisible corpus. Designed for xelatex (Hoefler Text body + Helvetica
% Neue marginalia + Hebrew fallback). Provides:
%
%   - Tufte-style sidenotes in the wide outer margin
%   - First-class commands for the v3 annotation primitive's three
%     presentation modes (\margin, \endnote, \inline) so the LaTeX
%     render of an annotated book matches what the HTML viewer shows
%   - A protocol-aware title page that renders the actual on-chain
%     header bytes as an intaglio stamp at the top
%   - Tone-byte decoration (ordinary / affection / demonic / ai /
%     reverence) on chapter rules + page headers
%   - \quipucite[anchor]{txid} for permanent on-chain citations
%   - A colophon environment for back-matter inscription metadata
%
% Usage:
%
%   \documentclass[essay,tone=ordinary]{colegio}    % single essay
%   \documentclass[book,tone=ordinary]{colegio}     % book / library
%
%   Options:
%     essay         — sectioning starts at \section (default top level)
%     book          — sectioning starts at \chapter (default top level)
%     tone=ordinary | affection | demonic | ai | reverence
%                   — sets tone-aware decoration; default ordinary
%
%   Commands the class adds:
%     \persona{El Gólem}                       % author persona
%     \inscribingaddress{multiman 2-of-2 …}    % address that signed it
%     \rootxid{7b19fb2b…}                       % root tx id
%     \blockheight{6{,}218{,}023}               % inscription block
%     \jointxid{3ea5e79b…}                      % join tx id (book only)
%     \protocolheader{c1 dd 00 01 09 00 |…|}   % on-chain header bytes
%
%     \margin{note md}              % v3 annotation, sidenote mode
%     \backnote{anchor}{note md}    % v3 annotation, endnote mode
%                                   % (anchor surfaces in "Notes" heading)
%     \inlinenote{note md}          % v3 annotation, inline-bracket mode
%     \unattached{anchor}{note md}  % renders in the colophon, anchor
%                                   % not located in body
%
%   The anchor is already in the prose at the call site — these macros
%   emit only the marker and the note. They do NOT re-emit the anchor.
%
%     \quipucite[anchor]{txid}      % styled citation to another quipu
%
%     \begin{colophon} … \end{colophon}
%                                   % back-matter inscription metadata
%
% Engine: xelatex required (fontspec, Unicode body).
%
% Author: El Gólem, for the Colegio Invisible (multiman 2-of-2)
% Version: 0.1 (2026-05-23)
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{colegio}[2026/05/23 v0.1 Colegio Invisible / Quipu Protocol class]

% --------------------------------------------------------------------
%   Option processing (needs xstring for IfSubStr / IfStrEq)
% --------------------------------------------------------------------
\RequirePackage{xstring}
\RequirePackage{etoolbox}
\RequirePackage{kvoptions}
\SetupKeyvalOptions{family=colegio,prefix=colegio@}

\DeclareBoolOption{essay}
\DeclareBoolOption{book}
\DeclareStringOption[ordinary]{tone}

\ProcessKeyvalOptions*\relax

% If neither essay nor book given, default to essay
\ifcolegio@book
\else
  \ifcolegio@essay
  \else
    \colegio@essaytrue
  \fi
\fi

% Validate tone option
\def\colegio@validtones{,ordinary,affection,demonic,ai,reverence,}
\edef\colegio@tonecheck{,\colegio@tone,}
\IfSubStr{\colegio@validtones}{\colegio@tonecheck}{}{%
  \ClassWarning{colegio}{Unknown tone='\colegio@tone'; falling back to ordinary}%
  \def\colegio@tone{ordinary}%
}

% --------------------------------------------------------------------
%   Base class
% --------------------------------------------------------------------
\ifcolegio@book
  \LoadClass[11pt,openany,oneside]{book}
\else
  \LoadClass[11pt,oneside]{article}
\fi

% --------------------------------------------------------------------
%   Required packages
% --------------------------------------------------------------------
\RequirePackage{fontspec}
\RequirePackage{xcolor}
% Page geometry: Tufte's B5 proportions, ported from tufte-common.def.
% Narrow tall textblock + wide outer marginpar for sidenotes. The
% paper is slightly larger than A5; the textwidth is similar to A5
% but the marginpar is generous so sidenotes have room to breathe.
\RequirePackage[paperwidth=176mm,paperheight=250mm,
                left=14.66mm,top=13.88mm,
                textwidth=102.66mm,
                marginparsep=7.33mm,marginparwidth=36.66mm,
                textheight=38\baselineskip,
                includehead]{geometry}
\RequirePackage{microtype}
\RequirePackage{graphicx}
\RequirePackage{eso-pic}      % full-bleed cover art (whole-page background layer)
\RequirePackage{caption}
\RequirePackage{marginnote}
\RequirePackage{titlesec}
\RequirePackage{fancyhdr}
\RequirePackage{enumitem}
\RequirePackage{tabularx}     % tables whose last column wraps to the measure
\RequirePackage{booktabs}     % \toprule \midrule \bottomrule
\RequirePackage{listings}     % verbatim code boxes (quipucode)
\RequirePackage[hidelinks]{hyperref}

% --------------------------------------------------------------------
%   Fonts (xelatex / fontspec) — match the Tufte-LaTeX class exactly
%
%   The upstream Tufte-LaTeX class loads:
%     \setmainfont[Renderer=Basic, Numbers=OldStyle, Scale = 1.0]{TeX Gyre Pagella}
%     \setsansfont[Renderer=Basic, Scale=0.90]{TeX Gyre Heros}
%     \setmonofont[Renderer=Basic]{TeX Gyre Cursor}
%
%   TeX Gyre Pagella is the free Palatino clone Tufte's classes use;
%   it has real OpenType small caps and old-style figures, so \textsc
%   resolves to a true SC shape and we don't need the faux-SC
%   machinery. Arial Hebrew remains the Hebrew fallback.
% --------------------------------------------------------------------
\setmainfont[
  Extension      = .otf,
  UprightFont    = *-regular,
  ItalicFont     = *-italic,
  BoldFont       = *-bold,
  BoldItalicFont = *-bolditalic,
  Numbers        = OldStyle,
  Scale          = 1.0,
]{texgyrepagella}
\setsansfont[
  Extension      = .otf,
  UprightFont    = *-regular,
  ItalicFont     = *-italic,
  BoldFont       = *-bold,
  BoldItalicFont = *-bolditalic,
  Scale          = 0.90,
]{texgyreheros}
\setmonofont[
  Extension      = .otf,
  UprightFont    = *-regular,
  ItalicFont     = *-italic,
  BoldFont       = *-bold,
  BoldItalicFont = *-bolditalic,
  Scale          = 0.86,
]{texgyrecursor}

% --------------------------------------------------------------------
%   Script fallbacks — Hebrew, Greek (polytonic), Arabic
%
%   The Quipu corpus is multilingual: Hebrew gematría, polytonic Greek
%   etymologies, Arabic star names. TeX Gyre Pagella covers Latin and
%   basic Greek but not polytonic accents or Arabic, so we register
%   per-script fallback families and let ucharclasses switch into them
%   automatically by Unicode block. Authors never have to wrap a Greek
%   word or an Arabic phrase — it just renders.
% --------------------------------------------------------------------
\newfontfamily{\hebrewfont}{Arial Hebrew}
\newfontfamily{\greekfont}{Times New Roman}
\newfontfamily{\arabicfont}{Arial Unicode MS}

\RequirePackage{ucharclasses}
\setTransitionsForGreek{\greekfont}{\normalfont}
\setTransitionsFor{Arabic}{\arabicfont}{\normalfont}
\setTransitionsFor{Hebrew}{\hebrewfont}{\normalfont}

% Most multilingual passages are handled automatically by the
% transitions above. The exception is a single word that mixes two
% Unicode blocks — e.g. polytonic Greek combining Greek-Extended
% (ἀ U+1F00) with Greek-and-Coptic (ή U+03AE) — where ucharclasses
% switches fonts mid-word and can drop the second block back to the
% Latin face. \gk / \ar / \he force one script font across the whole
% span and suspend the auto-switcher inside the group (interchar
% token state off), so a mixed-block word renders in one font.
\newcommand{\gk}[1]{{\XeTeXinterchartokenstate=0\relax\greekfont #1}}
\newcommand{\ar}[1]{{\XeTeXinterchartokenstate=0\relax\arabicfont #1}}
\newcommand{\he}[1]{{\XeTeXinterchartokenstate=0\relax\hebrewfont #1}}

% --------------------------------------------------------------------
%   Colors — bordado-gold palette
% --------------------------------------------------------------------
\definecolor{colegio@ink}      {HTML}{1a1a1a}
\definecolor{colegio@soft}     {HTML}{555555}
\definecolor{colegio@faint}    {HTML}{8a8a8a}
\definecolor{colegio@gold}     {HTML}{c2a76b}
\definecolor{colegio@wash}     {HTML}{faf6ec}
\definecolor{colegio@yellow}   {HTML}{e8b73a}
\definecolor{colegio@oxblood}  {HTML}{6e1a1a}
\definecolor{colegio@slate}    {HTML}{4a6b8a}
\definecolor{colegio@codebg}   {HTML}{efe9d8}

% Tone-specific accent color (used for chapter/section rules, page
% headers, annotation markers). Precomputed to a simple string macro
% at class load so it expands cleanly inside \color{...} arguments.
\IfStrEq{\colegio@tone}{ordinary} {\def\colegio@toneaccent{colegio@gold}}    {%
\IfStrEq{\colegio@tone}{affection}{\def\colegio@toneaccent{colegio@yellow}}  {%
\IfStrEq{\colegio@tone}{demonic}  {\def\colegio@toneaccent{colegio@oxblood}} {%
\IfStrEq{\colegio@tone}{ai}       {\def\colegio@toneaccent{colegio@slate}}   {%
\IfStrEq{\colegio@tone}{reverence}{\def\colegio@toneaccent{colegio@gold}}    {%
\def\colegio@toneaccent{colegio@gold}}}}}}

% Tone byte hex code, used in protocol-header rendering + colophon
\IfStrEq{\colegio@tone}{ordinary} {\def\colegio@tonebyte{00}}{%
\IfStrEq{\colegio@tone}{affection}{\def\colegio@tonebyte{01}}{%
\IfStrEq{\colegio@tone}{demonic}  {\def\colegio@tonebyte{0d}}{%
\IfStrEq{\colegio@tone}{ai}       {\def\colegio@tonebyte{a1}}{%
\IfStrEq{\colegio@tone}{reverence}{\def\colegio@tonebyte{ff}}{%
\def\colegio@tonebyte{00}}}}}}

\AtBeginDocument{\color{colegio@ink}}

% Hyperref colors
\hypersetup{
  colorlinks=true,
  linkcolor=colegio@ink,
  urlcolor=colegio@soft,
  citecolor=colegio@ink,
}

% Declare the colegiovolume TOC level to hyperref's bookmark machinery so
% nested-volume entries land at the right depth in the PDF outline. Without
% this declaration hyperref emits "bookmark level for unknown colegiovolume
% defaults to 0" warnings and the bookmark tree is flat at the master.
\RequirePackage{bookmark}
\bookmarksetup{numbered, open=false}
\AtBeginDocument{%
  \pdfstringdefDisableCommands{\let\colegio@toneaccent\@empty}%
}
\providecommand{\toclevel@colegiovolume}{-1}
% Plates float at the same depth as chapters in the TOC; declare the
% level so hyperref doesn't warn about it either.
\providecommand{\toclevel@plate}{0}

% --------------------------------------------------------------------
%   Captions + margin figures — Tufte convention
%
%   Tufte sets captions in the same small sans-serif as the sidenotes,
%   ragged, with the label run into the text rather than centered. And
%   the canonical Tufte figure is the *margin* figure: a small plate in
%   the wide outer margin, captioned in place, that the reader's eye
%   meets beside the prose that calls it.
% --------------------------------------------------------------------
\captionsetup{
  font       = {sf,footnotesize,color=colegio@soft},
  labelfont  = {sf,footnotesize},
  labelsep   = period,
  justification = raggedright,
  singlelinecheck = false,
}

% Art plates (0x5c TikZ compositions) are NOT figures of the essay they
% follow — they're their own sequence. A dedicated caption type gives
% them flat, chapter-independent numbering ("Plate 1", "Plate 2", …)
% under \platequipu, keeping them out of the per-chapter figure stream.
% \DeclareCaptionType binds the new counter to chapter (→ "Plate 5.1"),
% so detach it and force a plain arabic count.
\DeclareCaptionType{plate}[Plate][List of Plates]
\ifcolegio@book\counterwithout{plate}{chapter}\fi
\renewcommand{\theplate}{\arabic{plate}}

% \marginfigure{graphics}{caption} — drop a numbered figure into the
% outer margin. #1 is the graphics body (e.g. \includegraphics sized to
% \marginparwidth); #2 is the caption text. Numbered with the standard
% figure counter so margin and in-text figures share one sequence.
\newcommand{\marginfigure}[2]{%
  \marginnote{%
    \captionsetup{font={sf,scriptsize,color=colegio@soft},
                  labelfont={sf,scriptsize}}%
    #1\par\vspace{0.6mm}%
    \captionof{figure}{#2}%
  }%
}

% --------------------------------------------------------------------
%   On-chain image figures — \imagequipu / \imagequipuwide
%
%   An on-chain 0x03 image (or 0xce celestial) decoded to a PNG in
%   ./figures/ and placed as a figure with a quipu fingerprint credit.
%   These are the canonical placements emitted by colegio_pipeline.py
%   from a render="margin" / render="full" directive, and are equally
%   usable by hand.
%
%     \imagequipu{png basename}{txid}{caption}            — margin figure
%     \imagequipuwide[width]{png basename}{txid}{caption}  — full column
%
%   `png basename` is the file under figures/ without the .png suffix. Figures
%   are UNNUMBERED and sit in context (Tufte) — the image appears beside the
%   prose that summons it, so there is no "Fig. N" and no cross-referencing.
% --------------------------------------------------------------------
\newcommand{\imagequipu}[3]{%
  \marginnote{%
    \captionsetup{font={sf,scriptsize,color=colegio@soft},
                  labelfont={sf,scriptsize}}%
    \includegraphics[width=\marginparwidth]{figures/#1}\par\vspace{0.6mm}%
    \captionof*{figure}{#3}\par\vspace{0.3mm}%
    {\sffamily\fontsize{6}{7.5}\selectfont\color{colegio@faint}%
      \href{quipu:#2}{quipu:\StrLeft{#2}{8}\dots\StrRight{#2}{6}}\par}%
  }%
}
\newcommand{\imagequipuwide}[4][\linewidth]{%
  \begin{figure}[ht]
    \centering
    \includegraphics[width=#1]{figures/#2}%
    \caption*{#4}%
    \vspace{0.4mm}\par
    {\centering\sffamily\fontsize{6.5}{8}\selectfont\color{colegio@faint}%
      \textsc{image quipu}\,\,\href{quipu:#3}{\ttfamily quipu:#3}\par}%
  \end{figure}%
}

% --------------------------------------------------------------------
%   Certificate cards — \begin{certquipu} ... \end{certquipu}
%
%   A typeset certificate (type 0xcc), presented as a card that mirrors the
%   quipu browser's HTML popup: header chips, a body title, "by Artist",
%   an optional embedded image, optional prose, signatories listed by name
%   and public-key fragment, and an authority footer. Emitted by the
%   pipeline when an essay SHOWS a cert quipu via ![cap](<<txid>>).
% --------------------------------------------------------------------
\newenvironment{certquipu}{%
  \par\medskip\noindent
  \begin{minipage}{\linewidth}%
    \setlength{\parskip}{2pt}\setlength{\parindent}{0pt}%
    {\color{colegio@faint}\rule{\linewidth}{0.4pt}}\par
    \vspace{6pt}%
}{%
    \vspace{6pt}%
    {\color{colegio@faint}\rule{\linewidth}{0.4pt}}\par
  \end{minipage}%
  \par\medskip
}
% Top credit line of a cert card: the cert's own on-chain transaction id,
% set in the small "quipu reference" style with a clickable quipu: link.
\newcommand{\certheader}[1]{% full txid
  {\sffamily\fontsize{6.5}{8}\selectfont\color{colegio@faint}%
    \textsc{certificate}\,\,\href{quipu:#1}{\ttfamily quipu:#1}\par}%
  \vspace{4pt}%
}
% A small monospace chip — for hash-cert header fields like SHA256: 337095ad..
\newcommand{\certchip}[2]{%
  {\sffamily\fontsize{7.5}{10}\selectfont\color{colegio@soft}%
    \textsc{#1}\,\,{\ttfamily #2}}%
}
\newcommand{\certheaderchips}[1]{{#1\par\vspace{6pt}}}
% The hash cert's central feature — the full digest, set as a labeled block
% on its own (algo small-caps above, full hex digest in monospace beneath,
% breakable but printed entire). This is what the cert IS, not a chip.
\newcommand{\certhash}[2]{% algo, full hex digest
  {\sffamily\fontsize{7.5}{10}\selectfont\color{colegio@soft}%
    \textsc{#1 digest}\par}%
  \vspace{1pt}%
  {\ttfamily\fontsize{8}{10}\selectfont\color{colegio@ink}%
    \sloppy #2\par}%
  \vspace{6pt}%
}
% Title (the |TITLE| of an all-in-one, or a manual caption)
\newcommand{\certtitle}[1]{%
  {\fontsize{15}{19}\selectfont\itshape\color{colegio@ink}#1\par}%
}
\newcommand{\certartist}[1]{%
  \vspace{1pt}%
  {\itshape\fontsize{10}{13}\selectfont\color{colegio@soft}by~#1\par}%
}
% An embedded image (for an all-in-one's Image: field)
\newcommand{\certimage}[2]{% pngbasename, txid
  \vspace{6pt}%
  \begin{center}
    \includegraphics[width=0.8\linewidth,height=0.32\textheight,%
                     keepaspectratio]{figures/#1}%
  \end{center}%
  \vspace{-3pt}%
  {\centering\sffamily\fontsize{6.5}{8}\selectfont\color{colegio@faint}%
    \textsc{image quipu}\,\,\href{quipu:#2}{\ttfamily quipu:#2}\par}%
}
% Prose Text block
\newcommand{\certtextblock}[1]{%
  \vspace{6pt}%
  {\fontsize{10}{13.5}\selectfont #1\par}%
}
% Section divider inside the card (e.g. "SIGNATORIES")
\newcommand{\certsectionhead}[1]{%
  \vspace{8pt}%
  {\sffamily\fontsize{7.5}{10}\selectfont\color{colegio@soft}%
    \MakeUppercase{#1}\par}%
  {\color{colegio@faint}\rule{0.4\linewidth}{0.2pt}\par}%
  \vspace{2pt}%
}
% A signatory line: name + public-key fragment
\newcommand{\certsignatory}[2]{% name, pubkey_frag
  {\fontsize{9}{12}\selectfont\color{colegio@ink}#1\hspace{1em}%
    {\ttfamily\fontsize{8}{10}\selectfont\color{colegio@soft}#2}\par}%
}
% Authority footer line (CertificateAuthority)
\newcommand{\certauthority}[2]{% short_label, full_txid
  \vspace{8pt}%
  {\fontsize{9}{11}\selectfont\color{colegio@soft}Authority:\,%
    \href{quipu:#2}{\ttfamily #1}\par}%
}
% Inscription footer: the on-chain multisig address, its kind (e.g. "3-of-3
% multisig"), and the resolved names of the keys that signed.
\newcommand{\certinscription}[3]{% address, kind, signers ("A + B + C")
  \vspace{4pt}%
  {\fontsize{9}{11}\selectfont\color{colegio@soft}%
    Inscribed at {\ttfamily #1}\,\,$\cdot$\,\,#2\,\,$\cdot$\,\,signed by #3\par}%
}

% --------------------------------------------------------------------
%   \imagequipupair{pngL}{pngR}{caption}{txidL}{txidR}
%     A full-page-width DIPTYCH: two on-chain image subimages side by side
%     under one (unnumbered) caption, with both quipu references credited
%     beneath. Spans the text column + outer margin (\colegio@fullwidth),
%     the same widest measure as \platequipu.
% --------------------------------------------------------------------
\newcommand{\imagequipupair}[5]{%
  \begin{figure}[ht]
    \noindent\makebox[\textwidth][l]{%
      \begin{minipage}{\colegio@fullwidth}%
        \centering
        \begin{minipage}[c]{0.485\colegio@fullwidth}\centering
          \includegraphics[width=\linewidth,height=0.5\textheight,%
                           keepaspectratio]{figures/#1}%
        \end{minipage}\hfill
        \begin{minipage}[c]{0.485\colegio@fullwidth}\centering
          \includegraphics[width=\linewidth,height=0.5\textheight,%
                           keepaspectratio]{figures/#2}%
        \end{minipage}%
        \par\vspace{1.0mm}%
        \captionof*{figure}{#3}\par\vspace{0.4mm}%
        {\centering\sffamily\fontsize{6.5}{8}\selectfont\color{colegio@faint}%
          \textsc{image quipus}\,\,%
          \href{quipu:#4}{\ttfamily quipu:#4}\quad\,\,\,%
          \href{quipu:#5}{\ttfamily quipu:#5}\par}%
      \end{minipage}%
    }%
  \end{figure}%
}

% --------------------------------------------------------------------
%   In-flow image treatments + quipu provenance marks
%
%   Every DISPLAYED reference carries a quipu credit. Margin/full figures
%   credit it on a caption line; the in-flow treatments below carry a
%   superscript \quipusup that links to quipu:<txid>.
%
%     \imagequipuinline[width]{png}{txid}   — image in the text flow
%     \imagequiputhumb[width]{png}{txid}    — tiny raised thumbnail
%     \quipusup{txid}                       — superscript link to quipu:<txid>
% --------------------------------------------------------------------
\newcommand{\quipusup}[1]{%
  \textsuperscript{\href{quipu:#1}{\sffamily\fontsize{5.5}{6.5}\selectfont
    \color{colegio@faint}q}}%
}
\newcommand{\imagequipuinline}[3][\linewidth]{%
  \includegraphics[width=#1]{figures/#2}\quipusup{#3}%
}
\newcommand{\imagequiputhumb}[3][12mm]{%
  \raisebox{-0.3\height}{\includegraphics[width=#1]{figures/#2}}\quipusup{#3}%
}

% --------------------------------------------------------------------
%   \marginsee{title}{txid}{excerpt} — a Tufte "see also" margin card for a
%   text / essay / book quipu referenced with render="margin": the work's
%   title (linked to quipu:<txid>), a short excerpt, and the quipu credit.
%   The lightweight middle ground between an invisible cite and a full embed.
% --------------------------------------------------------------------
\newcommand{\marginsee}[3]{%
  \marginnote{%
    {\sffamily\fontsize{6.5}{8}\selectfont\color{colegio@soft}\textsc{see also}\par}%
    \vspace{0.3mm}%
    {\itshape\fontsize{8.5}{10.5}\selectfont\href{quipu:#2}{#1}\par}%
    \ifblank{#3}{}{\vspace{0.3mm}{\fontsize{8}{10}\selectfont\color{colegio@soft}#3\par}}%
    \vspace{0.4mm}{\sffamily\fontsize{6}{7.5}\selectfont\color{colegio@faint}%
      \href{quipu:#2}{quipu:\StrLeft{#2}{8}\dots\StrRight{#2}{6}}\par}%
  }%
}

% --------------------------------------------------------------------
%   \quoteby{attribution} — the attribution line of a block quotation.
%   Emitted by the pipeline at the end of a blockquote whose last line is an
%   attribution (`— Author, *Work*, Year`). Flush-right, em-dashed; the author
%   is set in small caps by the pipeline. Reads as a cited quotation; the
%   *Work* may itself be a quipu citation (a quipu: link).
% --------------------------------------------------------------------
\newcommand{\quoteby}[1]{%
  \par\nopagebreak\vspace{0.4mm}%
  {\raggedleft\sffamily\fontsize{8.5}{11}\selectfont\color{colegio@soft}%
    \textemdash\,#1\par}%
}

% --------------------------------------------------------------------
%   Code boxes — \begin{quipucode} … \end{quipucode}
%
%   A verbatim, monospace, lightly-shaded box for showing the literal
%   multiline source of markdown, LaTeX, glTF, Python, etc. Verbatim means
%   backslashes, braces, #, %, _ print exactly as written and indentation is
%   preserved. Emitted by colegio_pipeline.py from a fenced ``` block; the
%   fence's language is shown as a small label above the box (\quipucodelang).
% --------------------------------------------------------------------
\lstdefinestyle{quipustyle}{%
  basicstyle=\ttfamily\fontsize{8.3}{10.5}\selectfont\color{colegio@ink},
  backgroundcolor=\color{colegio@codebg},
  frame=single,
  framerule=0.4pt,
  rulecolor=\color{colegio@faint},
  framesep=7pt,
  xleftmargin=7pt, xrightmargin=7pt,
  aboveskip=1.1\baselineskip, belowskip=0.7\baselineskip,
  breaklines=true, breakindent=14pt, columns=fullflexible,
  keepspaces=true, showstringspaces=false, upquote=true, extendedchars=true,
  tabsize=2,
}
\lstnewenvironment{quipucode}{\lstset{style=quipustyle}}{}
% A small language label printed just above a code box.
\newcommand{\quipucodelang}[1]{%
  \par\vspace{0.6\baselineskip}\nopagebreak
  {\sffamily\fontsize{6.5}{8}\selectfont\color{colegio@faint}#1\par}%
  \nopagebreak\vspace{-0.3\baselineskip}%
}

% --------------------------------------------------------------------
%   Full-width plate figures — text column + outer margin
%
%   Tufte reserves three figure widths: margin-only (\marginfigure /
%   \imagequipu), text-column (\imagequipuwide), and full-width — the
%   figure spans the text block AND the outer sidenote margin, the
%   widest measure on the page. Art plates (0x5c TikZ compositions)
%   print at the full-width measure: a numbered, captioned, in-flow
%   figure that overhangs into the outer margin rather than a bare
%   full-bleed page.
%
%   \colegio@fullwidth = \textwidth + \marginparsep + \marginparwidth.
% --------------------------------------------------------------------
\newlength{\colegio@fullwidth}
\setlength{\colegio@fullwidth}{\textwidth}
\addtolength{\colegio@fullwidth}{\marginparsep}
\addtolength{\colegio@fullwidth}{\marginparwidth}

% \platequipu{pdf/png basename}{caption}{txid} — a full-width plate that
% spans column + outer margin. The plate takes its OWN dedicated page
% with an empty page style (no running header), so it reads as a
% standalone leaf rather than a continuation of the preceding essay.
% Left-anchored in a \textwidth slot so the box overhangs into the outer
% margin; sized to the page so the composition prints as large as the
% full-width measure allows. Numbered figure caption + quipu credit.
\newcommand{\platequipu}[3]{%
  \clearpage
  \thispagestyle{empty}%
  \null\vfill
  \noindent\makebox[\textwidth][l]{%
    \begin{minipage}{\colegio@fullwidth}%
      \centering
      \includegraphics[width=\colegio@fullwidth,height=0.84\textheight,%
                       keepaspectratio]{figures/#1}\par
      \vspace{3mm}%
      \captionof{plate}{#2}\par\vspace{0.6mm}%
      {\sffamily\fontsize{6.5}{8}\selectfont\color{colegio@faint}%
        \textsc{quipu reference}\,\,\href{quipu:#3}{\ttfamily quipu:#3}\par}%
    \end{minipage}%
  }%
  \vfill
  \clearpage
}

% \plateinline{pdf basename}{caption}{txid} — the SAME 0x5c plate set SMALL
% and in-flow, where the prose summons it (rather than full-page in the
% gallery). A plate may appear both ways in one book: a small inline
% citation at the point of discussion, and the full-page plate in the
% gallery at the end. Set as an UNNUMBERED in-context figure (no "Plate N"
% — the gallery owns the numbering), text-column width, with the same
% quipu credit beneath in the small caption style.
\newcommand{\plateinline}[3]{%
  \begin{figure}[ht]
    \centering
    \includegraphics[width=0.72\linewidth,height=0.34\textheight,%
                     keepaspectratio]{figures/#1}\par
    \vspace{0.6mm}%
    {\captionsetup{font={sf,scriptsize,color=colegio@soft}}%
      \captionof*{figure}{#2}}\par\vspace{0.3mm}%
    {\centering\sffamily\fontsize{6}{7.5}\selectfont\color{colegio@faint}%
      \textsc{quipu reference}\,\,\href{quipu:#3}{\ttfamily quipu:#3}\par}%
  \end{figure}%
}

% --------------------------------------------------------------------
%   Per-document metadata commands
% --------------------------------------------------------------------
\newcommand{\colegio@persona}{}
\newcommand{\persona}[1]{\renewcommand{\colegio@persona}{#1}}

% The institution behind the author. On the title page the byline reads
% "{Institution}: {Author}" when an institution is set (the cover art carries
% the institution alone). Set from the book's `institution=` header field.
\newcommand{\colegio@institution}{}
\newcommand{\institution}[1]{\renewcommand{\colegio@institution}{#1}}

\newcommand{\colegio@inscaddr}{}
\newcommand{\inscribingaddress}[1]{\renewcommand{\colegio@inscaddr}{#1}}

\newcommand{\colegio@rootxid}{}
\newcommand{\rootxid}[1]{\renewcommand{\colegio@rootxid}{#1}}

\newcommand{\colegio@jointxid}{}
\newcommand{\jointxid}[1]{\renewcommand{\colegio@jointxid}{#1}}

\newcommand{\colegio@blockheight}{}
\newcommand{\blockheight}[1]{\renewcommand{\colegio@blockheight}{#1}}

\newcommand{\colegio@protoheader}{}
\newcommand{\protocolheader}[1]{\renewcommand{\colegio@protoheader}{#1}}

\newcommand{\colegio@quipudate}{}
\renewcommand{\date}[1]{\renewcommand{\colegio@quipudate}{#1}}

% Title-page epigraph (Tufte): a quote set in small caps on the title page.
% Set from the book's `epigraph=` header field by the pipeline.
\newcommand{\colegio@epigraph}{}
\newcommand{\titleepigraph}[1]{\renewcommand{\colegio@epigraph}{#1}}

% --------------------------------------------------------------------
%   Title page
% --------------------------------------------------------------------
\renewcommand{\maketitle}{%
  \begin{titlepage}
    \thispagestyle{empty}
    \color{colegio@ink}
    \raggedright
    \null
    \vspace*{18mm}

    % Protocol header bytes (intaglio stamp at the top, left-aligned)
    {\ttfamily\fontsize{7}{9}\selectfont
      \color{colegio@soft}\colegio@protoheader\par}

    \vspace*{32mm}

    % Title — Tufte: italic, large, no rule, no small caps
    {\fontsize{28}{32}\selectfont\itshape\@title\par}

    \vspace{4mm}

    % Byline — institution and author. With an institution set the title page
    % reads "{Institution}: {Author}"; otherwise the author/persona alone.
    \ifx\colegio@institution\@empty
      \ifx\colegio@persona\@empty
        {\fontsize{13}{16}\selectfont\itshape\color{colegio@soft}\@author\par}
      \else
        {\fontsize{15}{18}\selectfont\itshape\color{colegio@soft}\colegio@persona\par}
      \fi
    \else
      {\fontsize{15}{18}\selectfont\itshape\color{colegio@soft}%
        \colegio@institution\ifx\colegio@persona\@empty\else: \colegio@persona\fi\par}
    \fi

    % Epigraph — a quote in small caps (Tufte title-page convention)
    \ifx\colegio@epigraph\@empty\else
      \vspace{14mm}
      {\scshape\fontsize{9.5}{14}\selectfont\color{colegio@soft}
        \rightskip=2em\relax\colegio@epigraph\par}
    \fi

    \vfill

    % Foot block — tone + date + block, all sans, all small, all left
    {\sffamily\fontsize{8}{11}\selectfont\color{colegio@soft}
      \uppercase\expandafter{\colegio@tone}\,\;$\cdot$\;\,tone byte 0x\colegio@tonebyte\par
      \ifx\colegio@quipudate\@empty\else
        \colegio@quipudate\par
      \fi
      \ifx\colegio@blockheight\@empty\else
        Dogecoin block \colegio@blockheight\par
      \fi
    }
  \end{titlepage}%
}

% --------------------------------------------------------------------
%   Page headers — Tufte convention
%
%   No rule above or below the header. Running head carries the title /
%   chapter mark (small caps) on one side and the page number on the
%   other; Tufte's "folios at the corner" rather than centered footer.
% --------------------------------------------------------------------
\pagestyle{fancy}
\fancyhf{}
\renewcommand{\headrulewidth}{0pt}
\renewcommand{\footrulewidth}{0pt}

% \volumemark{Title} — set the running volume title for subsequent
% pages. Pipeline emits this at the top of each nested volume; the
% running header then carries the volume name in small italic above the
% chapter mark, so a reader can always tell which volume a duplicate
% "Prologue" or "Afterword" belongs to. An empty title (the default,
% set in book-level prose outside any volume) suppresses the line.
\newcommand{\colegio@volumemark}{}
\newcommand{\volumemark}[1]{\renewcommand{\colegio@volumemark}{#1}}

\ifcolegio@book
  % Strip the default "Chapter N." prefix so the running head shows only
  % the chapter title; suppress the section mark entirely so the chapter
  % and section names can't collide in the (one-sided) head. Tufte runs a
  % single mark per page plus the folio at the outer corner — and the
  % volume title above when one is set.
  \renewcommand{\chaptermark}[1]{\markboth{#1}{#1}}
  \renewcommand{\sectionmark}[1]{}
  \fancyhead[L]{%
    \fontsize{8}{10}\selectfont\color{colegio@soft}%
    \ifx\colegio@volumemark\@empty\else
      {\itshape\fontsize{7}{8}\selectfont\colegio@volumemark}\\[-1pt]%
    \fi
    \textsc{\leftmark}%
  }
  \fancyhead[R]{\fontsize{8}{10}\selectfont\color{colegio@soft}\thepage}
\else
  \fancyhead[L]{\fontsize{8}{10}\selectfont\color{colegio@soft}\textsc{\@title}}
  \fancyhead[R]{\itshape\fontsize{8}{10}\selectfont\color{colegio@soft}\colegio@persona\quad\thepage}
\fi

% Chapter opening pages: Tufte's "plain" style — no header at all,
% folio unexpressed. (From Tufte's _Beautiful Evidence_: chapter
% opens do not carry running heads.)
\fancypagestyle{plain}{%
  \fancyhf{}%
  \renewcommand{\headrulewidth}{0pt}%
  \renewcommand{\footrulewidth}{0pt}%
}

% --------------------------------------------------------------------
%   Section / chapter formatting — Tufte convention
%
%   Italics (not small caps, not bold) at every level. No rules under
%   chapter titles. Chapter number rendered in a small sans-serif strap
%   line above, italic chapter title below — minimal, restrained, and
%   typographically quiet.
% --------------------------------------------------------------------
\ifcolegio@book
  \titleformat{\chapter}[display]
    {\relax}%
    {\sffamily\fontsize{8}{10}\selectfont\color{colegio@soft}%
      Chapter \thechapter}%
    {6pt}%
    {\fontsize{22}{26}\selectfont\itshape}%
    []
  \titlespacing*{\chapter}{0pt}{6\baselineskip}{2\baselineskip}
\fi

\titleformat{\section}[hang]
  {\normalfont\Large\itshape}%
  {\color{colegio@soft}\thesection}%
  {1em}{}
\titlespacing*{\section}{0pt}{2\baselineskip}{0.6\baselineskip}

\titleformat{\subsection}[hang]
  {\normalfont\large\itshape}%
  {\color{colegio@soft}\thesubsection}%
  {1em}{}
\titlespacing*{\subsection}{0pt}{1.4\baselineskip}{0.4\baselineskip}

% --------------------------------------------------------------------
%   \newthought{first words} — Tufte's small-caps lead-in
%
%   Marks the start of a new "thought" inside a section. The first few
%   words are rendered in small caps, set flush-left with a little extra
%   vertical space above so the new thought breathes. Use it to open
%   chapters, to start the body of a section, or anywhere a new
%   movement begins inside running prose.
% --------------------------------------------------------------------
\newcommand{\newthought}[1]{%
  \addvspace{1.0\baselineskip plus 0.5ex minus 0.2ex}%
  \noindent\textsc{#1}%
}

% --------------------------------------------------------------------
%   First-paragraph-after-heading: no indent
%
%   Tufte convention: the paragraph immediately following a chapter or
%   section title sits flush-left with no indent. The starred form of
%   \titlespacing (used above) handles this for \chapter / \section /
%   \subsection. After \maketitle we set it explicitly so the very
%   first paragraph of the body — which has no heading above it — also
%   sits flush-left. (Users can still open with \newthought if they
%   want the small-caps lead-in as well.)
% --------------------------------------------------------------------
\g@addto@macro\maketitle{\@afterindentfalse\@afterheading}

% --------------------------------------------------------------------
%   v3 annotation commands — \margin, \backnote, \inlinenote
%
%   The anchor phrase is already in the prose at the call site — the
%   user typed it as normal text. These macros emit ONLY the marker
%   and the note in its declared mode. They do NOT re-emit the anchor.
%
%   The v3 protocol's "anchor matching" semantics apply when the
%   binding is tunneled from another inscription; in a hand-typeset
%   LaTeX document the anchor is right there, so we just attach.
%
%   Backnote takes the anchor as a first argument for use in the
%   collected "Notes" section heading (so the reader knows what each
%   note is about). Margin and inline don't need it — the marker is
%   immediately adjacent to the anchor.
% --------------------------------------------------------------------

% Counter for annotations (used for marker numbers)
\newcounter{colegio@ann}

% Counter for nested-book volumes (a 0x09 sub-book rendered as a bound volume)
\newcounter{colegiovol}

% TOC line for a nested volume's title — one notch ABOVE \part, so the
% anthology's Contents reads Volume > Part > Chapter > Section. Set in italic at
% a larger size, generous space above, no leader dots, page number flush right.
% (Emitted by the pipeline as \addcontentsline{toc}{colegiovolume}{title}.)
\newcommand*\l@colegiovolume[2]{%
  \addpenalty{-\@highpenalty}%
  \addvspace{2.4em \@plus\p@}%
  \begingroup
    \parindent\z@ \rightskip\@pnumwidth \parfillskip-\@pnumwidth
    \leavevmode
    {\fontsize{14}{18}\selectfont\itshape\color{colegio@ink}#1}%
    \nobreak\hfil\nobreak
    \hb@xt@\@pnumwidth{\hss{\normalfont\normalsize\color{colegio@soft}#2}}%
    \par\nobreak\vskip 0.3em
  \endgroup}

% Scratch counters for save/restore of the chapter AND plate counters when a
% nested volume restarts its own numbering at 1 (a volume is its own book, so
% its chapters and its plates both count from one). One slot per nesting depth
% (A/B/C) so a sub-sub-book resumes the parent's counts in LIFO order.
\newcounter{colegiochapsaveA}
\newcounter{colegiochapsaveB}
\newcounter{colegiochapsaveC}
\newcounter{colegioplatesaveA}
\newcounter{colegioplatesaveB}
\newcounter{colegioplatesaveC}
\newcounter{colegiopartsaveA}
\newcounter{colegiopartsaveB}
\newcounter{colegiopartsaveC}

% Render an anchor marker (numeric superscript in tone-accent color)
\newcommand{\colegio@annmarker}[1]{%
  \textsuperscript{\sffamily\fontsize{6}{7}\selectfont
    \color{\colegio@toneaccent}#1}%
}

% \margin{note} — Tufte sidenote in the outer margin
\newcommand{\margin}[1]{%
  \stepcounter{colegio@ann}%
  \colegio@annmarker{\thecolegio@ann}%
  \marginpar{%
    \sffamily\fontsize{7.5}{10}\selectfont\color{colegio@soft}
    \colegio@annmarker{\thecolegio@ann}%
    \,#1%
  }%
}

% \backnote{anchor}{note} — collected at the end of the document
% (renamed from \endnote to avoid conflict with the endnotes package /
% hyperref's bundled endnote macro; the v3 protocol mode is still
% called endnote semantically, this is just the LaTeX command name.)
%
% List initialized with \let so the empty-list test \ifx \X \@empty
% works correctly when nothing has been appended.
\let\colegio@backnotelist\@empty
\newcommand{\backnote}[2]{%
  \stepcounter{colegio@ann}%
  \colegio@annmarker{\thecolegio@ann}%
  \protected@xappto\colegio@backnotelist{%
    \protect\item[\protect\colegio@annmarker{\thecolegio@ann}]%
    \protect\textit{on \protect\textquotedblleft#1\protect\textquotedblright.}%
    \protect\quad
    \unexpanded{#2}\protect\par
  }%
}
\newcommand{\printbacknotes}{%
  \ifx\colegio@backnotelist\@empty\else
    \vspace{10mm}
    {\color{\colegio@toneaccent}\rule{42mm}{0.3pt}\par}
    \vspace{3mm}
    {\sffamily\fontsize{8}{10}\selectfont\color{colegio@soft}
      \textsc{Notes}\par}
    \vspace{2mm}
    \begin{list}{}{%
      \setlength{\leftmargin}{8mm}
      \setlength{\itemindent}{0mm}
      \setlength{\labelsep}{2mm}
      \setlength{\itemsep}{2mm}
      \fontsize{8.5}{11}\selectfont\color{colegio@soft}
    }
      \colegio@backnotelist
    \end{list}
  \fi
}

% --------------------------------------------------------------------
%   Quipu bibliography — a references section listing every other
%   inscription a document cites or embeds. Each \quipubibitem row
%   gives the work's title, its type, and a clickable quipu:<txid>
%   address (the canonical on-chain reference, never an explorer URL).
%   Emitted by colegio_pipeline.py for books, collected across chapters.
%
%     \begin{quipubibliography}
%       \quipubibitem{Title}{0x01 essay}{<txid>}
%       …
%     \end{quipubibliography}
% --------------------------------------------------------------------
\newenvironment{quipubibliography}{%
  \vspace{8mm}
  {\color{\colegio@toneaccent}\rule{42mm}{0.3pt}\par}
  \vspace{3mm}
  {\sffamily\fontsize{8}{10}\selectfont\color{colegio@soft}
    \textsc{References}\par}
  \vspace{3mm}
  \begin{list}{}{%
    \setlength{\leftmargin}{7mm}%
    \setlength{\itemindent}{-7mm}%
    \setlength{\labelsep}{0pt}%
    \setlength{\itemsep}{1.8mm}%
    \fontsize{8.5}{11}\selectfont\color{colegio@ink}
  }%
}{%
  \end{list}
}
% \quipubibitem{title}{type label}{txid}
\newcommand{\quipubibitem}[3]{%
  \item \textit{#1}\quad
    {\sffamily\fontsize{7}{9}\selectfont\color{colegio@faint}#2}\\[0.2mm]
    {\ttfamily\fontsize{7.5}{9.5}\selectfont\color{colegio@soft}%
      \href{quipu:#3}{quipu:#3}}%
}

% --------------------------------------------------------------------
%   Reference Index — the back-matter appendix that lists every quipu,
%   address, and key referenced anywhere in the volume. Three macros for
%   the three reference kinds; each emits a clickable URL with the
%   scheme handler the canonical resolver registers:
%
%     \quipurefitem{txid}{type label}{title} → quipu:<txid>
%     \addrrefitem{address}{description}     → addr:<address>
%     \keyrefitem{pubkey}{description}       → key:<pubkey>
%
%   Pipeline-emitted by colegio_pipeline.py when a book manifest carries
%   a `tag: index` entry. The `refindex` environment wraps the three
%   sorted sub-tables; `\refindexsection{Title}` emits the section head.
% --------------------------------------------------------------------
\newenvironment{refindex}{%
  \vspace{4mm}
  {\color{\colegio@toneaccent}\rule{42mm}{0.3pt}\par}
  \vspace{2mm}
  {\sffamily\fontsize{7.5}{9}\selectfont\color{colegio@soft}
    \textsc{Reference Index}\par}
  \vspace{1.5mm}
  \setlength{\parindent}{0pt}%
  \setlength{\parskip}{0pt}%
}{%
  \vspace{3mm}
}
% --------------------------------------------------------------------
%   \widequipuindex environment — wraps the quipu-list rows of the
%   reference index in a full-page-width container, so each row
%   (txid + type label + title) sits on one line without the title
%   wrapping. The container is the same `\textwidth + marginsep +
%   marginparwidth` measure plates use, anchored to the text-column
%   left edge and overhanging into the outer sidenote margin.
% --------------------------------------------------------------------
% Each \quipurefitem inside this env gets a NEGATIVE right skip equal to
% the outer margin width, so the line stretches into the sidenote margin
% (gaining ~44mm beyond the text column) while still breaking
% page-to-page normally. A minipage approach would prevent page breaks;
% \rightskip is the right primitive for "let lines run into the margin
% without changing block-level layout."
\newenvironment{widequipuindex}{%
  \par\nopagebreak
  \setlength{\leftskip}{0pt}%
  \setlength{\rightskip}{-\dimexpr\marginparwidth+\marginparsep\relax}%
  \setlength{\parindent}{0pt}%
  \setlength{\parskip}{0pt}%
}{%
  \par\setlength{\rightskip}{0pt}%
}
\newcommand{\refindexsection}[1]{%
  \vspace{2.5mm}
  {\sffamily\fontsize{7.5}{9.5}\selectfont\color{colegio@soft}
    \MakeUppercase{#1}\par}
  {\color{colegio@faint}\rule{0.35\linewidth}{0.2pt}\par}
  \vspace{1mm}
}
% Quipu row: small ttfamily txid (clickable) + tiny type label + italic title
\newcommand{\quipurefitem}[3]{%
  \noindent
  {\ttfamily\fontsize{6.2}{7.6}\selectfont\color{colegio@soft}%
    \href{quipu:#1}{#1}}\quad
  {\sffamily\fontsize{5.5}{7}\selectfont\color{colegio@faint}#2}\quad
  {\itshape\fontsize{6.8}{8.2}\selectfont\color{colegio@ink}#3}\par
  \vspace{0.1mm}%
}
% Address row: ttfamily address (clickable) + label
\newcommand{\addrrefitem}[2]{%
  \noindent
  {\ttfamily\fontsize{6.2}{7.6}\selectfont\color{colegio@soft}%
    \href{addr:#1}{#1}}\quad
  {\itshape\fontsize{6.8}{8.2}\selectfont\color{colegio@ink}#2}\par
  \vspace{0.1mm}%
}
% Key row — name first (italic), then the pubkey wrapped onto two lines so
% the 128-char hex string doesn't run off the page. Pipeline pre-splits the
% hex into two halves (line1 / line2); the macro emits them stacked under
% the name. The whole hex is the href text so a click on either half lands
% on the same key: URI.
\newcommand{\keyrefitem}[3]{%
  \vspace{0.4mm}%
  {\itshape\fontsize{7}{8.5}\selectfont\color{colegio@ink}#3}\par
  {\ttfamily\fontsize{5.6}{7}\selectfont\color{colegio@soft}%
    \href{key:#1#2}{#1\hspace*{0pt}\\#2}}\par
  \vspace{0.6mm}%
}

% \inlinenote{note} — bracketed inline insertion at the call site
\newcommand{\inlinenote}[1]{%
  \stepcounter{colegio@ann}%
  \colegio@annmarker{\thecolegio@ann}%
  \,{\sffamily\fontsize{8.5}{10.5}\selectfont\color{colegio@soft}%
    [\,#1\,]}%
}

% \unattached{anchor}{note} — anchor doesn't appear in body; rendered
% only in the colophon's "unattached annotations" block.
\let\colegio@unattachedlist\@empty
\newcommand{\unattached}[2]{%
  \protected@xappto\colegio@unattachedlist{%
    \protect\item \protect\textit{#1\protect\textemdash}\unexpanded{ #2}\protect\par
  }%
}

% --------------------------------------------------------------------
%   \quipucite[anchor]{txid} — styled citation to another quipu
% --------------------------------------------------------------------
% Rendered as a clickable `quipu:<txid>` hyperlink so a reader (or the
% quipu: scheme handler / gateway behind the publication platform) can
% launch the cited inscription's renderer from the link.
% \allowbreak before the citation gives TeX a legal line-break point right
% before the (unbreakable) anchor+superscript unit, so it can move the whole
% unit to the next line instead of overflowing the measure; \nobreak between
% the anchor and its superscript keeps them together.
\newcommand{\quipucite}[2][]{%
  \allowbreak\href{quipu:#2}{%
    \ifx\\#1\\%
      % No anchor: show a TRUNCATED quipu: address inline (the full txid
      % lives in the link target and in the Reference Index). Printing the
      % whole 64-char hex in monospace can't line-break and overflows the
      % measure; the 12-char head + ellipsis is unambiguous and fits.
      {\ttfamily\fontsize{8.5}{10}\selectfont\color{colegio@soft}%
        quipu:\StrLeft{#2}{12}\dots}%
    \else
      \textit{#1}\nobreak\,%
      \textsuperscript{\sffamily\fontsize{6}{7}\selectfont
        \color{colegio@faint}quipu:\StrLeft{#2}{8}\dots}%
    \fi
  }%
}

% \quipusubcite{txid}{subobject}{anchor} — cite a NAMED element inside a
% structured quipu (a star in a celestial chart, a field in a cert, a drop in
% a keydrop): links to quipu:<txid>#<subobject>, anchored on the element name.
\newcommand*{\colegio@subnamelen}{0}
\newcommand{\quipusubcite}[3]{%
  \StrLen{#2}[\colegio@subnamelen]%
  \allowbreak\href{quipu:#1\##2}{%
    \textit{#3}\nobreak\,\textsuperscript{\sffamily\fontsize{6}{7}\selectfont
      \color{colegio@faint}quipu:\StrLeft{#1}{8}\dots\#%
      \ifnum\colegio@subnamelen>16\relax
        \StrLeft{#2}{12}\dots%
      \else
        #2%
      \fi
    }%
  }%
}

% --------------------------------------------------------------------
%   Colophon environment — back-matter inscription metadata
% --------------------------------------------------------------------
\newenvironment{colophon}{%
  \clearpage
  \thispagestyle{empty}
  \null\vspace*{0mm}
  \begin{center}
    {\color{colegio@gold}\rule{42mm}{0.4pt}}\par
    \vspace{6mm}
    {\sffamily\fontsize{8}{10}\selectfont\color{colegio@soft}
      \textsc{Colophon}\par}
    \vspace{8mm}
  \end{center}
  \sffamily\fontsize{8.5}{12}\selectfont\color{colegio@ink}
  \begin{list}{}{%
    \setlength{\leftmargin}{6mm}
    \setlength{\itemsep}{1.4mm}
  }
}{%
  \end{list}
  \vspace{6mm}
  % Print any unattached annotations
  \ifx\colegio@unattachedlist\@empty\else
    {\sffamily\fontsize{7}{9}\selectfont\color{colegio@soft}
      \textsc{Unattached annotations}\par}
    \vspace{2mm}
    \begin{list}{\textemdash}{%
      \setlength{\leftmargin}{6mm}
      \setlength{\itemsep}{1.4mm}
      \fontsize{8}{10.5}\selectfont\color{colegio@soft}
    }
      \colegio@unattachedlist
    \end{list}
  \fi
  \vfill
  \begin{center}
    {\color{colegio@gold}\rule{30mm}{0.15pt}}\par\vspace{2mm}
    {\sffamily\fontsize{6.5}{8}\selectfont\color{colegio@faint}
      c1\,dd\,00\,01 \,---\, quipu protocol \,---\, colegio invisible \,---\, mmxxvi\par}
  \end{center}
}

% Helper for use inside colophon: \colophonentry{label}{value}
\newcommand{\colophonentry}[2]{%
  \item {\color{colegio@soft}#1:} \quad
        \ifstrequal{#1}{root txid}{\ttfamily\fontsize{7.5}{9}\selectfont #2}{%
        \ifstrequal{#1}{join txid}{\ttfamily\fontsize{7.5}{9}\selectfont #2}{%
        #2}}%
}

% --------------------------------------------------------------------
%   Hyphenation + microtype niceties
%
%   Ragged-right body per Tufte — the eye glides down a uniform left
%   edge while the right edge tells the truth about line breaks rather
%   than disguising them with stretched word spacing. Paired with
%   generous hyphenation so the ragged column doesn't gape.
% --------------------------------------------------------------------
\RequirePackage{ragged2e}
\AtBeginDocument{\RaggedRight}
\setlength{\RaggedRightParindent}{1.2em}
% Let a ragged-right line end well short of the measure without penalty,
% so when the next token is an unbreakable box (a citation's quipu:
% provenance superscript, an inline \texttt protocol token) that would
% overflow, TeX prefers to break the line early and drop the box to the
% next line rather than poke it past the measure into the sidenote
% margin. The generous stretch is invisible in ragged-right (the right
% edge is already uneven); it only changes WHERE breaks are allowed.
\setlength{\RaggedRightRightskip}{0pt plus 4em}

\frenchspacing

\endinput
