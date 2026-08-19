# The dossier-generation prompt

Anthony's standing prompt for generating deep-research dossiers with another
model (e.g. ChatGPT deep research). Saved verbatim 2026-08-19 so it persists
across sessions and both instances, instead of living only in a Telegram
thread. Use it as-is; `[NAME]` / `[name]` is the only substitution point.

---

[NAME]
Please conduct a comprehensive, source-driven research dossier on this person.
I want the fullest reconstructable life history, from beginning to end of life, or from birth to the present if the person is still living.
Reconstruct the person's life chronologically and in detail. Include, wherever available:
full name, alternative names, pseudonyms, titles, nicknames
birth and death dates
birthplaces, residences, migrations, travels, exiles, imprisonments
family background, ancestry, parents, siblings, spouses, partners, children
education, teachers, mentors, formative influences
friendships, collaborators, enemies, patrons, rivals, political associates
employment, professions, institutions, companies, organizations
businesses, investments, technologies, inventions, patents, projects
political activity
religious, philosophical, ideological, artistic, or intellectual development
major journeys and geographical movements
important meetings and relationships
significant successes and failures
wealth, finances, business structures, property, and financial relationships where relevant
lawsuits, investigations, scandals, accusations, fraud, corruption, money laundering, criminal activity, intelligence connections, political violence, abuses, or other controversies where relevant
awards, honors, offices, appointments, dismissals
illnesses, addictions, psychological crises, accidents, injuries, and causes of death where documented
posthumous reputation, cult, influence, historical reinterpretation, and legacy
Include the good and the bad without judgment.
Do not sanitize inconvenient material because it is politically sensitive, ideologically inconvenient, defamatory in tone, or useful to one side of a political conflict. At the same time, do not present accusations as established facts without evidence.
For controversial material, clearly distinguish documented fact, allegation, investigation, indictment, formal charge, court finding, conviction, disputed claim, unverified claim, propaganda, rumor, legend, myth, and unresolved question.
Do not dismiss a factual claim merely because it has been used as propaganda. Investigate the underlying claim independently.
Do not use fact-checking articles as substitutes for investigating the primary claim. Use them as one source among others and trace their evidence back to underlying documents whenever possible.
Myth is as important as fact.
Include legends, hagiography, hostile mythology, conspiracy narratives, rumors, self-created mythology, propaganda, folklore, symbolic associations, and stories told about the person.
For significant myths or disputed stories, explain:
what the story says
when and where it appears
who circulated it
what evidence exists for or against it
how it affected the person's reputation
Keep factual history and myth distinguishable, but treat both as historically significant.
Give as complete a bibliography as reasonably possible of works authored, co-authored, edited, dictated, attributed to, or published under the person's name, including books, essays, articles, manifestos, speeches, interviews, diaries, correspondence, memoirs, technical papers, patents, artworks, films, recordings, compositions, or other relevant works.
Distinguish genuine authorship from posthumous collections, edited compilations, ghostwritten material, disputed attribution, and works merely published under the person's name. Give original publication dates and original-language titles where possible.
Also give a substantial bibliography and filmography of important works about the person, including biographies, memoirs, academic studies, investigative books, hostile biographies, sympathetic biographies, documentaries, films, television programs, podcasts, archival collections, and major long-form journalism.
Search broadly and deeply.
Prefer primary documents, archival material, government records, court records, company filings, financial disclosures, contemporaneous newspapers, correspondence, memoirs, interviews, academic publications, reputable books, specialist historical databases, investigative journalism, and strong local-language sources.
Do not rely primarily on Wikipedia or encyclopedia summaries. They may be used for orientation, but follow their citations into stronger underlying sources whenever possible.
Search in the person's native language and other relevant languages when useful.
Look for obscure material, contradictory accounts, forgotten episodes, local reporting, archival references, and details that commonly disappear from short biographies.
Where sources disagree, give the competing versions with names, dates, and sources rather than silently choosing one.
If an exact date, location, amount, relationship, or event cannot be established, say so explicitly and give the strongest available possibilities.
I want a research dossier, not an essay and not a moral evaluation.
Write without editorial overlay.
Avoid moralizing, ideological framing, apologetics, denunciation, praise, rhetorical conclusions, telling me what to think, or using identity or political affiliation as a shortcut for deciding whether a claim is true or false.
Favor documentary presentation: names, dates, places, events, quotations where useful, documentary evidence, competing accounts, and source attribution.
Do not compress the biography merely to make it elegant. Detail is preferable to brevity.
Use Markdown and organize the dossier with sections appropriate to the person's life, including where relevant:
Basic Identifying Information
Family and Ancestry
Childhood and Early Life
Education and Formation
Early Career
Chronological Life History
Companies, Institutions, Technologies, Projects, and Financial Interests
Political / Religious / Intellectual / Artistic Development
Important Relationships and Networks
Controversies, Allegations, Investigations, Crimes, Fraud, Corruption, or Financial Questions
Myths, Legends, Rumors, Propaganda, and Disputed Narratives
Works by the Person
Books and Major Works About the Person
Films, Documentaries, Interviews, and Archival Material
Death / Later Life / Present Status
Posthumous Reputation and Legacy
Chronology
End with a compact date-by-date or year-by-year timeline of the most important events.
Sources
At the very bottom, provide one deduplicated list of every URL actually used in preparing the dossier.
Source-list requirements:
one URL per line
full ordinary URLs beginning with https://
no ChatGPT citation syntax
no shortened links
no duplicate URLs
usable outside ChatGPT
include only sources actually consulted or relied upon
Output Requirement
Return the completed dossier as an actual downloadable .md file attachment. Do not return the dossier only as inline chat text.
Name the file:
[name]_research_dossier.md
The file must contain the complete dossier in clean Markdown, including the full deduplicated source list at the bottom.
If necessary, provide only a brief sentence in chat with the download link to the .md file.
Do not omit significant material simply because the resulting dossier is long.
