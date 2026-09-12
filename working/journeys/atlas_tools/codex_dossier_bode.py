#!/usr/bin/env python3
"""codex_dossier_bode.py -- run the Codex dossier machine ONCE for one Bode constellation.

    python3 atlas_tools/codex_dossier_bode.py <slug> "<Display Name>" <brief.md>

Like codex_dossier_zodiac.py, with the constellation prompt
(working/bode/PROMPT_TEMPLATE_CONSTELLATION.md) and the dossier written to
working/bode/<slug>.dossier.md. Separate from the atlas: no roster addendum.
"""
import os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
WJ = os.path.abspath(os.path.join(HERE, ".."))
BODE = os.path.abspath(os.path.join(WJ, "..", "bode"))
LAB = os.path.expanduser("~/codex_lab")
CODEX = os.path.expanduser("~/.local/bin/codex")


def log(msg):
    line = time.strftime("%m-%d %H:%M:%S ") + "[bode] " + msg
    print(line, flush=True)
    open(f"{LAB}/batch.log", "a").write(line + "\n")


def build_prompt(name, brief_path):
    tpl = open(f"{BODE}/PROMPT_TEMPLATE_CONSTELLATION.md").read().split("---", 1)[1].strip()
    tpl = tpl.replace("[NAME]", name).replace("[name]", name)
    brief = open(brief_path).read().split("---", 1)[1].strip()
    deliver = (f"\n\nUse web search extensively for sources, in English, Spanish, French, German, "
               f"Italian and Latin where the sources are. Run a DEDICATED contested-material pass: "
               f"search explicitly for \"{name}\" with dispute, misidentification, etymology, hoax, "
               f"controversy, obsolete, abolished, and the like; the dossier must engage the contested "
               f"material with the evidentiary labels rather than omit it. Write in English whatever the "
               f"language of the sources (quote other languages in the original with a gloss). Do not "
               f"attempt file writes or shell commands. Print the complete finished dossier, in full, as "
               f"your final message: a single Markdown document titled \"# {name}: Research Dossier\", "
               f"ending with the full list of source URLs.")
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
    os.makedirs(BODE, exist_ok=True)
    prompt = build_prompt(name, brief_path)
    open(f"{LAB}/prompt_bode_{slug}.txt", "w").write(prompt)
    logfile = f"{LAB}/run_bode_{slug}.log"
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
    open(f"{BODE}/{slug}.dossier.md", "w").write(doc)
    log(f"{slug}: DONE {doc.count(chr(10))} lines -> working/bode/{slug}.dossier.md")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
