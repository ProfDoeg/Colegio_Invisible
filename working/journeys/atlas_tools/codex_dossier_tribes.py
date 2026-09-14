#!/usr/bin/env python3
"""codex_dossier_tribes.py -- run the Codex dossier machine ONCE for one tribe of Israel.

    python3 atlas_tools/codex_dossier_tribes.py <slug> "<Display Name>" <brief.md>

Same shape as codex_dossier_bode.py, with the tribe prompt
(working/tribes/PROMPT_TEMPLATE_TRIBE.md) and the dossier written to
working/tribes/<slug>.dossier.md. Separate from the atlas: no roster addendum.
"""
import os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
WJ = os.path.abspath(os.path.join(HERE, ".."))
SET = os.path.abspath(os.path.join(WJ, "..", "tribes"))
TEMPLATE = f"{SET}/PROMPT_TEMPLATE_TRIBE.md"
TAG = "[tribes]"
LAB = os.path.expanduser("~/codex_lab")
CODEX = os.path.expanduser("~/.local/bin/codex")


def log(msg):
    line = time.strftime("%m-%d %H:%M:%S ") + TAG + " " + msg
    print(line, flush=True)
    open(f"{LAB}/batch.log", "a").write(line + "\n")


def build_prompt(name, brief_path):
    tpl = open(TEMPLATE).read().split("---", 1)[1].strip()
    tpl = tpl.replace("[NAME]", name).replace("[name]", name)
    brief = open(brief_path).read().split("---", 1)[1].strip()
    deliver = (f"\n\nUse web search extensively for sources, in English, Hebrew, Spanish, French, German "
               f"and Latin where the sources are; consult the Hebrew text, the Septuagint and the Vulgate "
               f"for the blessings; find Blavatsky's own pages (theosophy.world, the Theosophical "
               f"University Press online editions of The Secret Doctrine and Isis Unveiled, archive.org "
               f"scans) and quote them. Run a DEDICATED contested-material pass: search explicitly for "
               f"\"{name}\" with lost tribe, dispute, historicity, etymology, hoax, claim, and the like; "
               f"the dossier must engage the contested material with the evidentiary labels rather than "
               f"omit it. Write in English whatever the language of the sources (quote other languages "
               f"in the original with a gloss). Do not attempt file writes or shell commands. Print the "
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
    os.makedirs(SET, exist_ok=True)
    prompt = build_prompt(name, brief_path)
    open(f"{LAB}/prompt_tribes_{slug}.txt", "w").write(prompt)
    logfile = f"{LAB}/run_tribes_{slug}.log"
    log(f"{slug}: run ({name}), prompt {len(prompt)} chars")
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
    open(f"{SET}/{slug}.dossier.md", "w").write(doc)
    log(f"{slug}: DONE {doc.count(chr(10))} lines -> working/tribes/{slug}.dossier.md")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
