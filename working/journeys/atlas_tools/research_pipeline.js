export const meta = {
  name: 'atlas-research',
  description: 'Research one queue subject into a report.md and journey.json, clickless',
  phases: [
    { title: 'Gather', detail: 'five sonnet lenses over web + PDFs', model: 'sonnet' },
    { title: 'Verify', detail: 'two opus adversarial checkers', model: 'opus' },
    { title: 'Write', detail: 'opus drafts report + journey in house style', model: 'opus' },
    { title: 'Gate', detail: 'mechanical style checks + fix loop' },
    { title: 'Traducir', detail: 'opus writes the es/ version on its own terms', model: 'opus' },
  ],
}
// The atlas research pipeline. Sonnet gathers, Opus verifies and writes,
// the gate enforces house style mechanically. Fable orchestrates from the
// main loop. See docs/guides/research-pipeline.md.
const A = typeof args === 'string' ? JSON.parse(args) : args
const SLUG = A.slug
const NAME = A.name
const BRIEF = A.brief || ''
const DIR = A.dir                       // absolute path to working/journeys

const HOUSE = `HOUSE STYLE (non-negotiable):
- No em dash (—) anywhere in authored text. Use comma, semicolon, colon, or split into two real sentences (each with subject and predicate).
- Straight quotes only, never curly.
- campa: 450-650 characters each, present tense, third person, mythic register ("national mythology: the canon is true"). State facts; let juxtaposition interpret. No AI filler (no "significance inflation", no rule-of-three reflex, no summary closings). Tell this person's story at this place, on its own terms; never mention "the atlas," "this corpus," or the project itself inside a campa -- that framing is for the viewer navigating the map, not for the prose.
- Vary how campas END. Do not let every campa in a file close on the same shape (a plain fact followed by one ironic or resonant zinger clause) -- read fine alone, an unmistakable AI tell across 25-45 of them in a row. Mix real endings: some stop flat on a fact or a date with no closing flourish at all; some end mid-scene on a physical detail; some end on a quote; some end on an open question the record itself leaves open; some end on the plainest possible sentence. A closing zinger is one tool among several, not the default shape for every stop in a file.
- quote fields are verbatim source text, optional (about a third of stops), untouched by style rules.
- Evidence discipline: every factual claim is [A] attested (with the source named) or [R] reconstruction/tradition. Flag contradictions between sources; do not silently resolve them. Inaccessible sources are named with the reason. Gaps are stated as gaps.

COMMAND STYLE (violations trigger manual permission prompts and ABORT the run):
- NEVER use cd. Absolute paths in every command; git runs as git -C /abs/path.
- NEVER use a bash heredoc (<<PY, <<'PY', <<EOF). For any python beyond a trivial
  single-quoted one-liner: FIRST use the Write tool to save the script to
  ${A.dir}/atlas_tools/_scratch_<yourlens>.py, THEN run
  python3 ${A.dir}/atlas_tools/_scratch_<yourlens>.py. Delete is unnecessary; leave scratch files in place.
- python3 -c is allowed only with the entire program in single quotes and no
  braces containing quote characters; when in doubt, use a script file.
- NEVER curl or wget; fetch pages with WebFetch and files with python urllib
  inside your script. NEVER wrap commands in timeout, nice, or env.`

const SCHEMA_ITEMS = {
  type: 'object',
  properties: { items: { type: 'array', items: { type: 'object', properties: {
    claim: { type: 'string' }, tag: { type: 'string', enum: ['A', 'R'] },
    source: { type: 'string' }, date: { type: 'string' },
    place: { type: 'string' }, lat: { type: 'number' }, lng: { type: 'number' },
    note: { type: 'string' },
  }, required: ['claim', 'tag', 'source'] } } },
  required: ['items'],
}

// ---- Phase 1: Gather (haiku) ------------------------------------------------
const LENSES = [
  { key: 'chronology', prompt: `Research the life chronology of ${NAME} (${BRIEF}). Use WebSearch and WebFetch on encyclopedias, academic pages, and primary-source translations. If a promising source is a PDF, download and read it: python3 -c "import urllib.request,pypdf,io; d=urllib.request.urlopen('URL').read(); r=pypdf.PdfReader(io.BytesIO(d)); print('\\n'.join(p.extract_text() for p in r.pages[:40]))". Return 20-40 dated life events as items: claim, tag A (documented, name the source) or R (tradition/reconstruction), source, date (ISO, use year-only precision honestly e.g. "1330"), place.` },
  { key: 'geography', prompt: `Research the journey geography of ${NAME} (${BRIEF}). For each place they verifiably or traditionally stopped, return an item with: place name, lat, lng (from the actual landmark: the specific mosque, port, tomb, not the modern city center), date if known, claim describing what happened there, tag A or R, source. 25-45 stops covering the whole life arc. Precision to 4 decimals where the landmark is known.` },
  { key: 'quotes', prompt: `Find verbatim quotations BY or ABOUT ${NAME} (${BRIEF}) from primary sources in translation (their own writings, chronicles, trial records, letters). Return items: claim = the exact quotation, source = work + translator/edition, tag A only if you actually saw the text in a source you fetched; tag R if widely attributed but unverified by you. NEVER invent or paraphrase-as-quote. 8-15 items. Skip anything you cannot trace.` },
  { key: 'interlock', prompt: `Read the atlas at ${DIR}: Grep the *.journey.json files (and QUEUE.md, census_real_persons_2026-08-02.md) for people, places, and dates that intersect the life of ${NAME} (${BRIEF}). Return items: claim = the connection (who/where/when they cross an existing traveler's path), source = the file, tag A if the file states it, R if inferred. Include canonical pins to inherit: search geography like the Kaaba (21.4225, 39.8262), Temple Mount (31.778, 35.2354), Paris (48.8566, 2.3522), Buenos Aires (-34.6037, -58.3816). 10-20 items.` },
  { key: 'afterlife', prompt: `Research the afterlife and iconography of ${NAME} (${BRIEF}): tomb and its fate, editions and translations of their work, monuments, legends that grew later, modern rediscovery. Return 8-15 items: claim, tag, source, date, place with lat/lng where a real site exists.` },
]
const gathered = await parallel(LENSES.map(l => () =>
  agent(l.prompt + '\n\n' + HOUSE, { label: `gather:${l.key}`, phase: 'Gather', schema: SCHEMA_ITEMS, model: 'sonnet', effort: 'medium' })
))
const pool = {}
LENSES.forEach((l, i) => { pool[l.key] = (gathered[i] && gathered[i].items) || [] })
log(`gathered: ${Object.entries(pool).map(([k, v]) => k + '=' + v.length).join(' ')}`)

// ---- Phase 2: Verify (opus, adversarial) -----------------------------------
const VERDICTS = {
  type: 'object',
  properties: { verdicts: { type: 'array', items: { type: 'object', properties: {
    index: { type: 'integer' }, lens: { type: 'string' },
    verdict: { type: 'string', enum: ['CONFIRMED', 'CORRECTED', 'REJECTED', 'UNVERIFIABLE'] },
    correction: { type: 'string' },
  }, required: ['index', 'lens', 'verdict', 'correction'] } } },
  required: ['verdicts'],
}
const factPayload = JSON.stringify({ chronology: pool.chronology, geography: pool.geography, afterlife: pool.afterlife })
const quotePayload = JSON.stringify(pool.quotes)
const [factCheck, quoteCheck] = await parallel([
  () => agent(`You are the adversarial fact checker for an atlas entry on ${NAME}. A research model gathered these claims. Your job is to REFUTE: re-search the most doubtful dates, places, and coordinates (WebSearch/WebFetch; read PDFs with python3+pypdf if needed). Dates off by years, coordinates pointing at the wrong place, legends tagged [A] that are actually [R], events that never happened. For each item you checked return a verdict (index within its lens array, lens name, CONFIRMED/CORRECTED/REJECTED/UNVERIFIABLE, correction text with source when CORRECTED). Prioritize: every [A] tag, every coordinate, every date that anchors the chronology. Check at least 25 items.\n\nCLAIMS: ${factPayload}`,
    { label: 'verify:facts', phase: 'Verify', schema: VERDICTS, model: 'opus', effort: 'high' }),
  () => agent(`You are the quote authenticator for an atlas entry on ${NAME}. AI-invented quotations are the single worst failure this pipeline can produce. For EVERY quote below: trace it to a citable source by searching; if you cannot see the words in a real source, verdict REJECTED. Return one verdict per quote (index, lens="quotes", verdict, correction = the traced source or reason for rejection).\n\nQUOTES: ${quotePayload}`,
    { label: 'verify:quotes', phase: 'Verify', schema: VERDICTS, model: 'opus', effort: 'high' }),
])
const allVerdicts = [...((factCheck && factCheck.verdicts) || []), ...((quoteCheck && quoteCheck.verdicts) || [])]
for (const v of allVerdicts) {
  const arr = pool[v.lens]
  if (!arr || !arr[v.index]) continue
  if (v.verdict === 'REJECTED') arr[v.index]._rejected = true
  else if (v.verdict === 'CORRECTED') arr[v.index].note = ((arr[v.index].note || '') + ' CORRECTED: ' + v.correction).trim()
  else if (v.verdict === 'UNVERIFIABLE' && arr[v.index].tag === 'A') arr[v.index].tag = 'R'
}
for (const k of Object.keys(pool)) pool[k] = pool[k].filter(x => !x._rejected)
log(`after verify: ${Object.entries(pool).map(([k, v]) => k + '=' + v.length).join(' ')} (verdicts applied: ${allVerdicts.length})`)

// ---- Phase 3: Write (opus) --------------------------------------------------
const writeResult = await agent(`Write the two atlas artifacts for ${NAME} (slug: ${SLUG}) from this verified research pool:\n${JSON.stringify(pool)}\n\nFirst READ two existing exemplars for form: ${DIR}/abdelkader.journey.json (schema and campa register) and ${DIR}/bourlemont_roster.md (report method). Then Write BOTH files:\n\n1. ${DIR}/${SLUG}.report.md - the research report: sections by life phase, every claim tagged [A source] or [R], contradictions flagged not resolved, honest gaps, a Sources section listing what was reachable and what was not. 8-20 KB.\n\n2. ${DIR}/${SLUG}.journey.json - top-level keys traveler, title, years, register (exactly "national mythology: the canon is true"), calendar ("julian" for pre-1582 lives, "gregorian" after), segments: 5-9 named segments, each with stops in travel order. Each stop: name (Place, the event - colon form, no dash), lat, lng, date (full ISO; default unknown month/day to 01), date_confidence (the scholarly hedge lives HERE, never in prose), campa (450-650 chars, the narrative), quote + quote_source (only where the verified pool has a real one), sources (list), suggested_refs (list). 25-45 stops. Inherit canonical pins EXACTLY where the interlock lens found them (byte-identical, e.g. Kaaba 21.4225, 39.8262). Name another existing atlas traveler in a campa ONLY where ${NAME} themself has a direct or indirect relation to that person (met them, corresponded, was influenced by/influenced them, family, rivalry, cited them, wrote substantively about them even one-directionally across centuries -- a commentator writing on a historical or biblical figure is a real link even though the reverse could never be true, etc.) -- never merely because both happened to pass through the same place or time. Shared geography alone is not a reason to name-drop; the atlas's own map already shows co-location to a viewer.\n\n${HOUSE}\n\nReturn JSON: {report_path, journey_path, stops, segments, interlocks: [slugs named in campa]}.`,
  { label: 'write', phase: 'Write', schema: { type: 'object', properties: { report_path: { type: 'string' }, journey_path: { type: 'string' }, stops: { type: 'integer' }, segments: { type: 'integer' }, interlocks: { type: 'array', items: { type: 'string' } } }, required: ['report_path', 'journey_path', 'stops', 'segments', 'interlocks'] }, model: 'opus', effort: 'high' })

// ---- Phase 4: Gate (mechanical + one fix loop) ------------------------------
const gate = await agent(`Run the style gate on ${DIR}/${SLUG}.journey.json and ${DIR}/${SLUG}.report.md.\n\nMechanical checks via python3 (write a throwaway script with json+re): (1) journey.json parses; (2) every stop has name, lat (number), lng (number), date, campa; (3) every campa 450-650 chars; (4) zero em dashes (—) and zero curly quotes in campa, name, title, and the report body OUTSIDE quotations/quote fields; (5) register field exactly "national mythology: the canon is true"; (6) dates within each segment non-decreasing (year precision); (7) report has [A and [R tags and a Sources section; (8) search every campa field for the bare word "atlas" (case-insensitive) and for "this corpus"/"the corpus" (case-insensitive). Do NOT auto-fix these and do NOT fail the gate over them -- almost always a real self-reference to the project, but Anthony wants a human okay before anything gets rewritten, in case a hit is a genuine, non-self-referential use of the word. For every hit, APPEND (do not overwrite) one line to ${DIR}/pending_atlas_review.md in the form '- [ ] SLUG -- stop \"NAME\": \"...the matching sentence, quoted verbatim...\"', creating the file with a one-line header if it does not exist. Report the count of hits in the gate result but do not otherwise touch them.\n\nThen read the campa prose as the humanizer: kill AI tells (filler, inflation, rule-of-three reflex, summary closings) by EDITING the file - restructure sentences properly, never lazy-swap punctuation. Also check the shape of every campa's LAST sentence across the whole file: if most or all of them close on the same pattern (a plain fact, then one ironic or resonant zinger clause), that uniformity is itself an AI tell even though each sentence reads fine alone. Rewrite a good spread of them so endings vary in shape (some flat on a fact, some mid-scene on a detail, some on a quote, some on an open question, some with no closing flourish at all), without inventing content or dropping citations.\n\nFix every violation you find by editing the files, re-run the mechanical checks, and return {passed: true/false, violations_found: n, violations_fixed: n, remaining: [list]}.\n\n${HOUSE}`,
  { label: 'gate', phase: 'Gate', schema: { type: 'object', properties: { passed: { type: 'boolean' }, violations_found: { type: 'integer' }, violations_fixed: { type: 'integer' }, remaining: { type: 'array', items: { type: 'string' } } }, required: ['passed', 'violations_found', 'violations_fixed', 'remaining'] }, model: 'opus', effort: 'medium' })

// ---- Phase 5: Traducir (opus) ----------------------------------------------
const es = await agent(`Write the Spanish edition of the journey at ${DIR}/${SLUG}.journey.json as ${DIR}/es/${SLUG}.journey.json.\n\nFirst READ two files: the English original, and ${DIR}/es/abdelkader.journey.json as the exemplar of the Spanish corpus. Then Write the es/ file following the exemplar exactly:\n- register: exactly "mitología nacional: el canon es verdadero"\n- traveler unchanged; title, segment names, stop names, campa, and quotes rendered in Spanish\n- lat, lng, date, date_confidence, sources, suggested_refs copied unchanged\n- quote fields: translate the quotation into literary Spanish (use an established Spanish translation of the source when one is standard, e.g. Reina-Valera for scripture); quote_source keeps the work title as cited, descriptive words in Spanish\n\nTranslate on Spanish's own terms, not sentence-for-sentence: good Castilian prose in the corpus register (presente histórico, tercera persona). Where English needed a restructure, Spanish may solve it with a colon or the impersonal se (exemplar: "no se hacen escuelas construyendo salas; se hacen fabricando maestros"). campa may run 450-760 characters; Spanish breathes longer.\n\nESTILO (innegociable): sin raya (—) en texto propio; comillas rectas solamente; sin muletillas de IA (cabe destacar, juega un papel crucial, en el vasto mundo de, sin lugar a dudas, no es solo X sino Y); sin cierres de resumen; sin tríos clausales reflejos; sin anglicismos de traducción (eventualmente por finalmente, asumir por suponer).\n\nAfter writing, verify mechanically: Write a python script to ${DIR}/atlas_tools/_scratch_es.py (NEVER a heredoc, NEVER cd) that checks the es file parses, every stop keeps identical lat/lng/date to the English, campa 450-760, zero em dashes and curly quotes, register exact; run python3 on it and fix any violation. Return {es_path, stops, campa_ok, checks_passed}.`,
  { label: 'traducir', phase: 'Traducir', schema: { type: 'object', properties: { es_path: { type: 'string' }, stops: { type: 'integer' }, campa_ok: { type: 'boolean' }, checks_passed: { type: 'boolean' } }, required: ['es_path', 'stops', 'campa_ok', 'checks_passed'] }, model: 'opus', effort: 'high' })

return { slug: SLUG, pool_sizes: Object.fromEntries(Object.entries(pool).map(([k, v]) => [k, v.length])), verdicts: allVerdicts.length, write: writeResult, gate, es }