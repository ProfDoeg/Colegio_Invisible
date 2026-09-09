#!/usr/bin/env python3
"""codex_dossier_once.py -- run the Codex dossier machine ONCE for one subject
with a hand-crafted brief, outside the worklist runner.

    python3 atlas_tools/codex_dossier_once.py <slug> "<Display Name>" <brief.md>

Builds the prompt exactly as codex_dossier_runner.py does (PROMPT_TEMPLATE
body + name), then appends the brief (everything after its first '---'), the
runner's delivery instructions, and the roster addendum; runs `codex exec`
with web search; extracts the printed dossier; writes it to
~/codex_lab/out/<slug>.dossier.md and appends a status line to
~/codex_lab/batch.log. Staging into dossiers/ is left to the main loop.

Why: the runner takes subjects only from the catalog and its prompt has no
per-subject brief. Anthony's El Gólem request (2026-09-08) needed a custom
prompt assembling every manifestation of the legend plus LLM history.
"""
import os, re, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
D = os.path.abspath(os.path.join(HERE, ".."))
LAB = os.path.expanduser("~/codex_lab")
OUT = f"{LAB}/out"
CODEX = os.path.expanduser("~/.local/bin/codex")


def log(msg):
    line = time.strftime("%m-%d %H:%M:%S ") + "[once] " + msg
    print(line, flush=True)
    open(f"{LAB}/batch.log", "a").write(line + "\n")


def build_prompt(name, brief_path):
    tpl = open(f"{D}/dossiers/PROMPT_TEMPLATE.md").read().split("---", 1)[1].strip()
    tpl = tpl.replace("[NAME]", name).replace("[name]", name)
    brief = open(brief_path).read().split("---", 1)[1].strip()
    add = open(f"{D}/dossiers/ATLAS_CONNECTIONS_ADDENDUM.md").read().split("---", 1)[1].strip()
    deliver = (f"\n\nUse web search extensively for sources. Run a DEDICATED adversarial pass: "
               f"search explicitly for \"{name}\" combined with controversy, "
               f"antisemitism, propaganda, hoax, fabrication, criticism, dispute, and the like, "
               f"including the most recent two years; the dossier must engage the major negative "
               f"and contested material with the usual evidentiary labels rather than omit it. "
               f"Do not attempt file writes or shell commands. Print the complete finished "
               f"dossier, in full, as your final message: a single Markdown document titled "
               f"\"# {name}: Research Dossier\", including the Atlas Connections section, ending "
               f"with the full list of source URLs.")
    return tpl + "\n\nSUBJECT-SPECIFIC BRIEF (overrides the template where they differ):\n\n" + brief + deliver + "\n\n" + add


def extract(logtext, name):
    marker = f"# {name}: Research Dossier"
    i = logtext.rfind(marker)
    if i < 0:
        i = logtext.rfind("# " + name)
    if i < 0:
        return None
    return re.sub(r"\ntokens used\n[\d,]+\s*$", "\n", logtext[i:])


def main(slug, name, brief_path):
    os.makedirs(OUT, exist_ok=True)
    prompt = build_prompt(name, brief_path)
    open(f"{LAB}/prompt_{slug}.txt", "w").write(prompt)
    logfile = f"{LAB}/run_{slug}.log"
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
    open(f"{OUT}/{slug}.dossier.md", "w").write(doc)
    log(f"{slug}: DONE {doc.count(chr(10))} lines, held in out/ for review (once-run)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3]))
