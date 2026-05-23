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
\RequirePackage[a5paper,
                inner=12mm, outer=42mm,    % Tufte-style: wide outer for sidenotes
                top=18mm, bottom=18mm,
                marginparwidth=32mm,
                marginparsep=4mm]{geometry}
\RequirePackage{microtype}
\RequirePackage{graphicx}
\RequirePackage{caption}
\RequirePackage{titlesec}
\RequirePackage{fancyhdr}
\RequirePackage{enumitem}
\RequirePackage[hidelinks]{hyperref}

% --------------------------------------------------------------------
%   Fonts (xelatex / fontspec)
% --------------------------------------------------------------------
\setmainfont{Hoefler Text}
\setsansfont{Helvetica Neue}[Scale=0.86]
\setmonofont{Menlo}[Scale=0.84]
\newfontfamily{\hebrewfont}{Arial Hebrew}

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

% --------------------------------------------------------------------
%   Per-document metadata commands
% --------------------------------------------------------------------
\newcommand{\colegio@persona}{}
\newcommand{\persona}[1]{\renewcommand{\colegio@persona}{#1}}

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

% --------------------------------------------------------------------
%   Title page
% --------------------------------------------------------------------
\renewcommand{\maketitle}{%
  \begin{titlepage}
    \thispagestyle{empty}
    \color{colegio@ink}
    \begin{center}
      \null
      \vspace*{14mm}

      % Protocol header bytes (intaglio stamp at the top)
      {\ttfamily\fontsize{7}{9}\selectfont
        \color{colegio@soft}\colegio@protoheader\par}
      {\fontsize{6.5}{8}\selectfont\itshape
        \color{colegio@faint}
        c1\,dd\,00\,01 \,---\, magic\;$\cdot$\;type\;$\cdot$\;tone\;$\cdot$\;pipe-delimited header\par}

      \vspace*{20mm}

      % Title
      {\fontsize{22}{26}\selectfont
        \scshape\addfontfeature{Letters=UppercaseSmallCaps}
        \@title\par}

      \vspace{6mm}
      \begin{minipage}{0.65\textwidth}\centering
        {\color{colegio@gold}\rule{42mm}{0.4pt}}\par
      \end{minipage}
      \vspace{6mm}

      % Author / persona
      \ifx\colegio@persona\@empty
        {\fontsize{12}{15}\selectfont\itshape\@author\par}
      \else
        {\fontsize{14}{17}\selectfont\itshape\colegio@persona\par}
        \ifx\@author\@empty\else
          {\fontsize{8}{10}\selectfont\color{colegio@soft}
            \quad ---\, \@author \,---\par}
        \fi
      \fi

      \vfill

      % Tone marker
      {\sffamily\fontsize{8}{10}\selectfont\color{colegio@soft}
        \uppercase\expandafter{\colegio@tone}\,\;$\cdot$\;\,tone byte\;0x\colegio@tonebyte\par}

      \vspace{3mm}

      % Date / block
      \ifx\colegio@quipudate\@empty\else
        {\sffamily\fontsize{8}{10}\selectfont\color{colegio@soft}
          \colegio@quipudate\par}
      \fi
      \ifx\colegio@blockheight\@empty\else
        {\sffamily\fontsize{7.5}{10}\selectfont\color{colegio@faint}
          Dogecoin block \colegio@blockheight\par}
      \fi

      \vspace{6mm}

      % Bordado-gold double rule at the foot
      {\color{colegio@gold}\rule{42mm}{0.4pt}\par}
      \vspace{1pt}
      {\color{colegio@gold}\rule{42mm}{0.15pt}\par}

    \end{center}
  \end{titlepage}%
}

% --------------------------------------------------------------------
%   Page headers + tone-aware rule
% --------------------------------------------------------------------
\pagestyle{fancy}
\fancyhf{}
\renewcommand{\headrulewidth}{0pt}
\renewcommand{\footrulewidth}{0pt}

\ifcolegio@book
  \fancyhead[L]{\sffamily\fontsize{7}{9}\selectfont\color{colegio@soft}\leftmark}
  \fancyhead[R]{\sffamily\fontsize{7}{9}\selectfont\color{colegio@soft}\rightmark}
\else
  \fancyhead[L]{\sffamily\fontsize{7}{9}\selectfont\color{colegio@soft}\@title}
  \fancyhead[R]{\sffamily\fontsize{7}{9}\selectfont\color{colegio@soft}\colegio@persona}
\fi
\fancyfoot[C]{\sffamily\fontsize{7.5}{9}\selectfont\color{colegio@faint}\thepage}

% Override the header rule to draw it tone-colored, just below the headline
\renewcommand{\headrule}{%
  {\color{\colegio@toneaccent}\hrule height 0.3pt}%
  \IfStrEq{\colegio@tone}{reverence}{%
    \vskip 0.6pt
    {\color{\colegio@toneaccent}\hrule height 0.15pt}%
  }{}%
  \IfStrEq{\colegio@tone}{ai}{%
    \vskip 0.5pt
    {\color{\colegio@toneaccent}\hrule height 0.15pt}%
  }{}%
}

% --------------------------------------------------------------------
%   Section / chapter formatting
% --------------------------------------------------------------------
\ifcolegio@book
  \titleformat{\chapter}[display]
    {\normalfont\filcenter}%
    {\sffamily\fontsize{8}{10}\selectfont\color{colegio@soft}%
      Chapter \thechapter}%
    {6pt}%
    {\fontsize{20}{24}\selectfont\scshape}%
    [\vspace{2mm}{\color{\colegio@toneaccent}\rule{42mm}{0.4pt}}\vspace{2mm}]
\fi

\titleformat{\section}[hang]
  {\normalfont\fontsize{14}{17}\selectfont\scshape}%
  {\color{colegio@soft}\thesection\quad}%
  {0pt}{}

\titleformat{\subsection}[hang]
  {\normalfont\fontsize{11}{14}\selectfont\itshape}%
  {\color{colegio@soft}\thesubsection\quad}%
  {0pt}{}

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
    {\sffamily\fontsize{8}{10}\selectfont
      \scshape\color{colegio@soft} Notes\par}
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
\newcommand{\quipucite}[2][]{%
  \ifx\\#1\\%
    {\ttfamily\fontsize{8.5}{10}\selectfont\color{colegio@soft}%
      quipu:#2}%
  \else
    \textit{#1}\,%
    \textsuperscript{\sffamily\fontsize{6}{7}\selectfont
      \color{colegio@faint}quipu:\StrLeft{#2}{12}\dots}%
  \fi
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
    {\sffamily\fontsize{8}{10}\selectfont\scshape\color{colegio@soft}
      Colophon\par}
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
    {\sffamily\fontsize{7}{9}\selectfont\scshape\color{colegio@soft}
      Unattached annotations\par}
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
% --------------------------------------------------------------------
\sloppy
\frenchspacing

\endinput
