#!/usr/bin/env python3
"""codex_dossier_zodiac.py -- run the Codex dossier machine ONCE for one zodiac figure.

    python3 atlas_tools/codex_dossier_zodiac.py <slug> "<Display Name>" <brief.md>

Like codex_dossier_once.py, but with the zodiac prompt (working/zodiac/PROMPT_TEMPLATE_ZODIAC.md),
no atlas roster addendum (Anthony: separate from the atlas), and the finished dossier written
straight to working/zodiac/<slug>.dossier.md. Logs to ~/codex_lab/batch.log like the others.
"""
import os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
WJ = os.path.abspath(os.path.join(HERE, ".."))                      # working/journeys
ZODIAC = os.path.abspath(os.path.join(WJ, "..", "zodiac"))          # working/zodiac
LAB = os.path.expanduser("~/codex_lab")
CODEX = os.path.expanduser("~/.local/bin/codex")


def log(msg):
    line = time.strftime("%m-%d %H:%M:%S ") + "[zodiac] " + msg
    print(line, flush=True)
    open(f"{LAB}/batch.log", "a").write(line + "\n")


def build_prompt(name, brief_path):
    tpl = open(f"{ZODIAC}/PROMPT_TEMPLATE_ZODIAC.md").read().split("---", 1)[1].strip()
    tpl = tpl.replace("[NAME]", name).replace("[name]", name)
    brief = open(brief_path).read().split("---", 1)[1].strip()
    deliver = (f"\n\nUse web search extensively for sources, in English, Spanish, French, German, "
               f"Italian and Latin where the sources are. Run a DEDICATED contested-material pass: "
               f"search explicitly for \"{name}\" with dispute, misidentification, etymology, hoax, "
               f"controversy, precession, Ophiuchus, and the like; the dossier must engage the "
               f"contested material with the evidentiary labels rather than omit it. "
               f"Write in English whatever the language of the sources (quote other languages in the "
               f"original with a gloss). Do not attempt file writes or shell commands. Print the "
               f"complete finished dossier, in full, as your final message: a single Markdown document "
               f"titled \"# {name}: Research Dossier\", ending with the full list of source URLs.")
    return tpl + "\n\nFIGURE-SPECIFIC BRIEF (overrides the template where they differ):\n\n" + brief + deliver


def extract(logtext, name):
    marker = f"# {name}: Research Dossier"
    i = logtext.rfind(marker)
    if i < 0:
        i = logtext.rfind("# " + name)
    if i < 0:
        return None
    return re.sub(r"\ntokens used\n[\d,]+\s*$", "\n", logtext[i:])


def main(slug, name, brief_path):
    os.makedirs(ZODIAC, exist_ok=True)
    prompt = build_prompt(name, brief_path)
    open(f"{LAB}/prompt_zodiac_{slug}.txt", "w").write(prompt)
    logfile = f"{LAB}/run_zodiac_{slug}.log"
    log(f"{slug}: run ({name}), brief {os.path.basename(brief_path)}, prompt {len(prompt)} chars")
    home = os.path.expanduser("~")
    try:
        with open(logfile, "w") as lf:
            subprocess.run([CODEX, "exec", "-s", "workspace-write", "--skip-git-repo-check",
                            "-C", LAB, "-c", "tools.web_search=true", "-"],
                           input=prompt, stdout=lf, stderr=subprocess.STDOUT, text=True, timeout=7200,
                           env={**os.environ, "HOME": home, "PATH": f"{home}/.local/bin:" + os.environ.get("PATH", "")})
    except subprocess.TimeoutExpired:
        log(f"{slug}: TIMEOUT after 120 min"); return 2
    text = open(logfile).read()
    doc = extract(text, name)
    if not doc or re.search(r"\nERROR: ", doc):
        log(f"{slug}: no clean dossier in output, tail: " + text[-200:].replace("\n", " ")); return 1
    open(f"{ZODIAC}/{slug}.dossier.md", "w").write(doc)
    log(f"{slug}: DONE {doc.count(chr(10))} lines -> working/zodiac/{slug}.dossier.md")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
