# Sarah Bernhardt (1844-1923): research report

*2026-08-24. Written against the verified research pool for slug `sarah_bernhardt`, which had already been through an adversarial correction pass. Several of that pass's corrections overturn the first-round sources; they are carried here rather than silently absorbed.*

Legend: [A] attested, source named. [R] reconstruction, tradition, or single-source lead. *flagged* = two reachable sources disagree and the disagreement is left standing.

Output: `sarah_bernhardt.journey.json`, 9 segments, 45 stops, 10 quote fields.

---

## 0. Corrections carried against English Wikipedia

Eight errors were caught in the pool, all load-bearing. A reader checking the journey against en.wikipedia will find it disagreeing in each case, on purpose. These are not restated in the phase sections below.

| # | First-round claim | Correction, and what the journey carries |
|---|---|---|
| 1 | Birth 23 Oct 1844; variants "25 September", "1914" | 22 Oct is the *date officielle* (fr.wiki); 23 Oct in some biographies; 25 Oct on the plaque, called *erronée*; "25 September" unsourced; 1914 is the court decision reconstituting the act. Carried: 1844-10-22, variants in `date_confidence` |
| 2 | Baptized in a Paris parish, May 1856 | Baptized 1856 at Versailles, at the Grandchamp convent, names Sara Marie Henriette. Folded into the Grandchamp stop |
| 3 | *Le Passant* premiered 14 Jan 1868 | 1869 on both Coppée articles and fr.wiki; the English article contradicts its own ordering. Carried: 1869-01-14 |
| 4 | First *Phèdre* 1873 | fr.wiki gives 1874; the standard account gives 21 Dec 1874 at short notice, matching the "74 hours" anecdote. Carried: 1874, with 1873 flagged |
| 5 | Sociétaire 1878, welded to the balloon and fine | fr.wiki: "nomination 1875". Balloon and 1,000 fr fine stay 1878. Split into two stops |
| 6 | Mucha's *Gismonda* poster 1894 | Play premiered 31 Oct 1894; poster on the streets 1 Jan 1895. Both dated inside one stop |
| 7 | The theatre opened with *Hamlet* | Opened 21 Jan 1899 with *La Tosca*; prose *Hamlet* is May 1899. Two stops |
| 8 | Knee injury on the 1891 tour | The misplaced-mattress fall in Rio is 1905-06; fr.wiki traces the origin to an 1887 shipboard dislocation, TB of the bone diagnosed at Berlin 1902. 1891 and 1906 kept apart |

Three coordinate corrections, each checked against the source that fixes it: Booth's Theatre 40.7425/-73.9928 (pool figure ~360 m off); Teatro Politeama, Buenos Aires -34.6009/-58.3899 (~900 m off, near Plaza de Mayo); Pointe des Poulains 47.3850/-3.2469 (the pool carried *two* wrong figures for one place, 2.3 km and 6.8 km inland). The Montreal clerical attack was redated from 1880-81 to 1905; nothing fetched documents an 1880 version.

---

## 1. Origin, and the first Comédie-Française (1844-1863)

- Born Henriette-Rosine Bernard, Paris, 1844 [A en.wiki; fr.wiki]. The birthplace address is traditional: 48.8508/2.3406 sits on rue de l'École-de-Médecine, but no document places the birth in that house [R].
- Grandchamp, Versailles, Augustinian sisters, c. 1853-1859 [A en.wiki]. The dossier's baptism version (a named Paris church, 21 May, a register naming Édouard Bernhardt of Le Havre as father) is unsupported by anything fetched and is not carried [R, dropped].
- Conservatoire 1859-1862 on the Duc de Morny's recommendation; Provost, Samson, Régnier; second prize in tragedy [A en.wiki].
- Debut as Iphigénie, received as unsuccessful [A en.wiki]. *flagged*: en.wiki gives 31 August 1862, other accounts 11 August; the journey uses 31 August and says so.
- Departure after an incident involving Madame Nathalie, 15 January 1863 [A en.wiki]; the geography lens adds that it was a backstage slap. What started the quarrel is in nothing reachable, and the campa says so [gap].

**Gap.** Her mother, her mother's household, and the arrangement that put her in the Conservatoire are thinly sourced in reachable material. The journey names Morny and stops.

**R lead not used in prose.** The dossier claims she modelled her persona on the earlier Jewish tragédienne Rachel (Élisa Félix). Single-sourced, unconfirmed, and there is no `rachel.journey.json` to link against.

**Pin inheritance.** All six Comédie-Française stops use 48.8632, 2.3363, the corrected Salle Richelieu pin from `victor_hugo.journey.json`, byte-identical; that file records the Palais-Royal pin previously in circulation as 290 m off.

---

## 2. The wilderness, and the Odéon (1864-1872)

- Gymnase, small roles, 1864-1866 [A en.wiki]. Brussels, mid-1860s [R en.wiki, general terms only].
- Maurice Bernhardt born 22 December 1864, her only child [A en.wiki]. Paternity of Henri, Prince de Ligne: the standard account, corroborated but not documentary [R]. No address recoverable, so the canonical Paris pin is used and the campa states the gap.
- Odéon from 1866 at 150 francs a month [A en.wiki].
- Kean revival, 18 February 1868: the house riots, chanting for *Ruy Blas* and Hugo. The Figaro notice signed "Tonotus" is quoted by Bernhardt in her memoir, pp. 131-132, verified by archive.org search-inside [A]. The pool's most consequential correction: round one filed the line at p. 159 and read it as Bernhardt describing *another* actress, flagging it "so it is not mistaken for self-description." That reading is inverted. It is a press notice of Bernhardt herself, the earliest good evidence for the golden voice, and it is used as the Kean stop's quote, attributed to the Figaro critic.
- A claim that *Le Passant* was played before Napoleon III is dossier-only and kept out of the prose [R].
- Siege of Paris, Sept 1870 to Jan 1871: the Odéon converted to a military ambulance under her, 150+ wounded [A en.wiki]. Five memoir passages verified by search-inside (pp. 192, 194, 197, 207, 211), including Frantz Mayer of the Silesian Landwehr.
- Saint-Germain-en-Laye, 1871, refuge during the Commune [R en.wiki]. Cut from the journey as too thin to stage: no date, no address, no incident. Recorded so the cut is not silent.
- *Ruy Blas*, 16 January 1872; Hugo reportedly kissed her hand [A en.wiki; reported, not documented].

---

## 3. Sociétaire (1872-1880)

- Returned 1 October 1872 [A en.wiki].
- The dossier's ordinal "299th sociétaire" could not be verified: comedie-francaise.fr returned 404 and fr.wikipedia's *Liste des sociétaires* returned 404. The journey never uses it [gap].
- 35 rue Fortuny, 1876-1885, sold to cover debts [A en.wiki]. *Après la tempête*, honourable mention, Salon of 1876 [A dossier citing Musée d'Orsay, awarewomenartists.com].
- *Hernani*, 1877, and Hugo's tear-shaped pearl on a gold bracelet; balloon over Paris at the 1878 Exposition and the fine from Perrin [A en.wiki].
- Resignation, 1880, over a role in *L'Aventurière*; 100,000 francs damages; accrued pension reported at 43,000 forfeited [A en.wiki]. The month follows the geography lens; no source reachable gives a day [gap].

---

## 4. London and America (1879-1881)

- Gaiety Theatre, 4 June 1879, *Phèdre*, before an audience without French [A en.wiki]. Same season: an exhibition of her paintings and sculpture, a rented house in Chester Square with part of her menagerie, and the acquaintance with Oscar Wilde [A en.wiki, corroborated in `oscar_wilde.journey.json`].
- Le Havre 15 October 1880, New York 27 October, debut 8 November, *Adrienne Lecouvreur*, Booth's Theatre, 27 curtain calls; 157 performances in 51 cities, *La Dame aux camélias* 65 times [A en.wiki]. The $194,000 in gold is widely repeated press and promotional accounting, not an audited net, and is written as what the papers reported.
- Menlo Park, visit to Thomas Edison, lost experimental recording of *Phèdre* [R]: dossier-sourced, relayed by en.wiki. `thomas_edison.journey.json` contains no Bernhardt material; no cylinder, catalogue entry, or contemporary notice from either side was found. Coordinates 40.5631, -74.3394 inherited byte-identical from that file.
- Return to Paris 5 May 1881, cool reception [A en.wiki].

---

## 5. Damala and the long circuits (1881-1890)

- Kyiv and Odesa, 1881-82: antisemitic hostility from crowds; Alexander III at St Petersburg on the same tour [A en.wiki].
- Marriage to Aristide Damala, London, 4 April 1882 [A fr.wiki]: months long in fact, never dissolved, he dies 1889, generally attributed to morphine. The Ambigu-Comique run with him 1882-83, the *Fédora* premiere of 12 December 1882, and the February 1883 auction of jewellery, carriages and horses [A en.wiki].
- Ravenna, San Vitale, 1884, studying the Theodora mosaic for Sardou's *Théodora* [A dossier + en.wiki]. No exact date found; the month orders the segment [gap].
- 1886-87 Latin American circuit, roughly fifteen months, over 1,000,000 francs; Edward Jarrett dies on the road; in Rio, Pedro II attends and gives a diamond bracelet, later stolen, and yellow fever goes through her leading actors [A en.wiki].
- *La Tosca*, Porte Saint-Martin, 24 November 1887, 29 consecutive sold-out performances; *Jeanne d'Arc*, 1890, at 45 [A en.wiki].

**Buenos Aires is the largest gap in this file, and the one closest to the approved brief.** The Spanish Wikipedia article on the Teatro Politeama confirms the house operated 1879-1958 and that Bernhardt performed there, but gives no year; the 1886 dating comes only from the tour's overall span, and no venue-level date, programme, or Argentine press notice was recovered. The stop is tagged R throughout and its campa says the Argentine leg is "documented as a fact and blank as an evening." Next pass: Argentine newspaper archives (La Nación, La Prensa), 1886-87. Pin caution from `francesco_tamburini.journey.json`: her dates predate the 1908 new Teatro Colón, so the new-Colón pin at -34.601/-58.3831 used in `anna_pavlova.journey.json` must not be inherited here, and is not.

---

## 6. Around the world (1891-1893)

- The tour: Europe, Russia, the Americas, Australia, New Zealand, Hawai'i, Samoa; 45 costume crates, 75 clothing crates, 250 pairs of shoes; returns with 3,500,000 francs [A en.wiki]. Internal ordering is undocumented; only the span is fixed. Sydney is dated 1892-09-01 as an ordering convention. Auckland, Honolulu and Apia were cut rather than invented into a sequence; all three were R-tagged with no venue, date, or notice [gap, recorded].
- *Salomé*: Wilde wrote it in French in Paris, October 1891, expressly for her; she accepted; rehearsals began at London's Palace Theatre in June 1892; the Lord Chamberlain's examiner refused a licence under the rule against biblical figures on the English public stage [A `oscar_wilde.journey.json`]. She never played it, and the play reached the world through Strauss's 1905 opera. Palace Theatre coordinates (51.5128, -0.1298) were not verified against a gazetteer [gap, flagged in the stop].

---

## 7. Her own houses (1893-1900)

- Théâtre de la Renaissance taken over 1893 for a reported 700,000 francs [A en.wiki].
- Pointe des Poulains fort bought 11 November 1894, not 1886; summers there until 1922 [A fr.wiki *Pointe des Poulains*, corroborated by fr.wiki Bernhardt].
- Mucha [A `alphonse_mucha.journey.json` + en. *Alphonse Mucha*]. Pin inheritance: Théâtre de la Renaissance at 48.8706, 2.3554, the Mucha file's canonical figure, byte-identical; it differs by ~200 m from the geography lens's 48.8697/2.3583, and the Mucha file wins by the inheritance rule.
- Grand Hôtel banquet, 9 December 1896 [A dossier only]. Cut for space.
- Dreyfus: her alignment with Zola and the Dreyfusard camp is [R], dossier-sourced (forward.com; *French Historical Studies*, Duke UP), and `captain_alfred_dreyfus.journey.json` contains no mention of her. The stop is dated to *J'accuse*, 13 January 1898, purely to order the segment. Her 1856 Catholic baptism is [A fr.wiki] and is used as the pool frames it: it protected her from nothing on either side.
- Beerbohm's "truly grande dame" belongs to the May 1899 *Hamlet*, not to the January opening, and is used there [A en.wiki].
- *Le Duel d'Hamlet*, Clément Maurice, Phono-Cinéma-Théâtre programme, 1900 Exposition; synchronised sound now lost [A en.wiki]. The ~2-minute running time is dossier-only [R].

---

## 8. The farewell tours, the leg, the war (1901-1923)

- 1905-06 North American tour: locked out of major houses by the Theatrical Syndicate, playing tents, skating rinks, and a 4,500-seat travelling canvas theatre [A dossier].
- Montreal, 1905: the bishop encouraged his followers to throw eggs at her, over her sympathetic portrayals of prostitutes [A en.wiki]. Clerical objection on the 1880 tour is real in the literature but nothing fetched documents it, so it is not staged [gap].
- Rio, 1905-06: two competing accounts of the knee's origin are carried, neither resolved (see §0).
- *Judas*, New York, December 1910: halted after one performance, Boston and Philadelphia refusing it [A dossier]. Cut for space; a real stop a later pass could carry.
- Chevalier of the Légion d'honneur, 16 March 1914, minister René Viviani, cited for spreading French abroad and for her 1870-71 nursing [A en.wiki + fr.wiki]. The geography lens's 14 January 1914 is wrong and is not used. The 1921 promotion to Officier is dossier-only and not carried in prose [R].
- Amputation, 22 February 1915, right leg above the knee, Clinique Saint-Augustin, Bordeaux, Professor Jean-Henri Maurice Denucé, for bone tuberculosis [A fr.wiki]. The immobilisation under Pozzi and Denucé and her insistence on decisive surgery come from the dossier citing *The Lancet* and circulatingnow.nlm.nih.gov [A/R].
- Wartime performances 1915-1917 near Verdun and in the Argonne, seated, reclined, or carried [A en.wiki + dossier for the sectors]. No individual engagement date recovered [gap].
- Died 26 March 1923, 56 boulevard Pereire, of acute renal insufficiency, having collapsed during the filming of Guitry's *La Voyante* that month; funeral 29 March, buried in the 44th division of Père-Lachaise [A fr.wiki]. Press crowd figures are description, not a count.
- The coffin: fr.wiki describes the rosewood, white-satin-lined coffin she promoted through photographs and postcards and says she eventually used it for burial. That it was literally the same object as the publicity prop is [R], a later legend with no primary confirmation; the campa marks it as legend in the sentence itself.

**Compression note.** Documented events that got no stop of their own were folded into an adjacent campa, not dropped: Brussels, Le Havre, Chester Square, St Petersburg, the Ambigu-Comique, the 1883 auction, *Après la tempête*, the 1 January 1895 poster.

---

## 9. Quotes: verified and unverified

Verified verbatim by archive.org search-inside on `mydoublelifememo00bernuoft`, the 1907 D. Appleton translation of *Ma double vie*:

| p. | line | used on |
|---|---|---|
| 122 | *I went downstairs trembling, tottering, and my teeth chattering.* | 1862 debut |
| 123 | *Yes, I would do it again, quand-meme, if any one dared me again.* | 1863 slap; 1878 balloon |
| 131-132 | *...her rich voice, that astonishing voice of hers... like a little Orpheus* (Figaro, "Tonotus") | 1868 Kean |
| 192 | *The defence...was being organised, and I decided to use my strength and intelligence in tending the wounded.* | 1870 ambulance |
| 367-368 | *I was determined to play quand-meme.* | 1915 Bordeaux |
| 441 | *We ought to hate very rarely...forgive often and never forget.* | 1881 return to Paris |

Two of these sit on stops other than the events they describe (p. 123, a childhood dare; pp. 367-368, an 1870s *L'Étrangère* performance). In both cases `quote_source` states the real context, so the reader is never told the line was uttered at the stop it sits on. Verified but unused: pp. 194, 197, 207, and p. 211, the Frantz Mayer identification, narrated in prose instead.

Not verified, tagged as such in `quote_source`: *Life is short, even for those who live a long time...*, which Wikiquote cites to *My Double Life* ch. 33, though fetches truncated before that chapter [R]; *Once the curtain is raised, the actor ceases to belong to himself.*, cited by Wikiquote to *The Art of the Theatre* (1924/25) p. 171, of which no accessible full text was found [R]; and Beerbohm on her Hamlet, quoted in en.wiki but not traced to his own printed text [A at one remove].

---

## 10. Interlocks

Named in a campa, each on a direct relation Bernhardt herself had:

| slug | relation | tag |
|---|---|---|
| `victor_hugo` | the Odéon pit chants his name at her, 1868; the Queen in *Ruy Blas*, 1872, and he kisses her hand; Doña Sol in *Hernani*, 1877, and the tear-pearl bracelet | [A] |
| `alphonse_mucha` | she commissions the *Gismonda* poster, 26 Dec 1894, and contracts him for six years | [A] |
| `oscar_wilde` | met London 1879; he writes *Salomé* in French for her, Oct 1891; she accepts and rehearses it | [A] |
| `thomas_edison` | she visits Menlo Park on the 1880-81 tour | [R] |
| `captain_alfred_dreyfus` | she takes the Dreyfusard side publicly during the Affair | [R] |

Not named in any campa, because the relation runs *toward* her from someone else and staging it would break the stop-ownership rule: `paul_berthon`, whose 1901 lithograph of her his own file flags as carrying no evidence she sat for it, carried instead as a `suggested_ref` on the Mucha stop; and `marcel_proust`, whose La Berma scholars read as drawn on Rachel and on Bernhardt, though his file contains no Bernhardt mention, carried as a `suggested_ref` on the *Phèdre* stop [R]. `anna_pavlova`, `francesco_tamburini` and `torcuato_de_alvear` share only Buenos Aires geography and are not named.

Meta-finding: a corpus-wide grep of 699 journey files found no existing file mentioning Sarah Bernhardt by name. The Mucha and Wilde files already carry her name and are the natural candidates for a reciprocal `suggested_ref` when the operator next touches them.

---

## Apparatus relations for the operator

Sarah Bernhardt is **not** listed in `EXCEPTIONS.md`. No apparatus stops were written. Two classes of relation were caught that are not rooted in her own travelling, and per the standing rule they are reported rather than deleted.

**Direction caught: FORWARD (not licensable without the author's say-so).** Her afterlife postdates the file's clock, which stops on 29 March 1923. None of it is staged as a scene; all of it lives in `suggested_refs` or `date_confidence`.

1. The Théâtre Sarah-Bernhardt renamed Théâtre de la Cité by the German occupation authorities in 1941 because of her Jewish ancestry, name restored 1947, Théâtre de la Ville from 1968 [A en. *Théâtre de la Ville*]. The strongest posthumous item in the pool and the one most tempting to stage, since it closes the thread the Kyiv 1881 and Dreyfus 1898 stops open. It sits in a `suggested_ref` on the 1899 lease stop.
2. Espace muséographique Sarah Bernhardt, Pointe des Poulains. Sources conflict: fr.wiki Bernhardt says *depuis 2007*, fr.wiki *Pointe des Poulains* says acquired 2000, restored 2003-04, reopened 2005. Both given; neither asserted alone.
3. Petit Palais, *Sarah Bernhardt et la femme créa la star*, 2023 [A petitpalais.paris.fr]: a `suggested_ref` on the rue Fortuny stop.
4. BnF Arts du spectacle centenary presentation, 2023 [A bnf.fr]. Coordinate note: the pool's BnF figure 48.8830/2.3708 is not a BnF site, falling in the 19th arrondissement; Arts du spectacle is at Richelieu, ~48.8676/2.3382. No BnF stop is staged, but the wrong figure should not propagate.
5. Hollywood Walk of Fame star [A fr.wiki], no address or induction year recoverable, and Project Gutenberg ebook #9100, translator not surfaced. Both [gap], both unused.

**Direction caught: one-directional toward the subject (real, citable, not stageable).** Berthon's lithograph and Proust's La Berma, handled as in §10. Neither is rooted in an act of hers, so both stay in `suggested_refs`.

No forward grant is requested. If the author wants the 1941 name-stripping told as a scene rather than as apparatus, that would need Bernhardt added to `EXCEPTIONS.md`. Nothing has been written into any other file in either direction.

---

## Sources

**Reachable and used.** Wikipedia: `en.` and `fr.` *Sarah Bernhardt* (the English article is the chronology's spine and the source of several §0 errors; the French one is decisive on the birthdate, the Versailles baptism, the 1875 sociétariat, the Belle-Île purchase, the amputation and the burial); `fr. Pointe des Poulains`; `en. Gismonda`; `en. Alphonse Mucha`; `en. Booth's Theatre`; `en. Théâtre de la Ville`; `es. Teatro Politeama (Buenos Aires)`; `fr.`/`en. François Coppée`. Also: Sarah Bernhardt, *My Double Life*, English trans., New York: D. Appleton, 1907, archive.org `mydoublelifememo00bernuoft`, via search-inside; `petitpalais.paris.fr`; `bnf.fr`; Project Gutenberg ebook #9100. Atlas files consulted for pins and intersections: `alphonse_mucha`, `oscar_wilde`, `victor_hugo`, `thomas_edison`, `captain_alfred_dreyfus`, `paul_berthon`, `marcel_proust`, `anna_pavlova`, `francesco_tamburini`, `torcuato_de_alvear`.

**Checked and negative, or unreachable: recorded as gaps.**

- comedie-francaise.fr sociétaire register: 404. The "299th sociétaire" ordinal is unverified and unused.
- fr.wikipedia, *Liste des sociétaires de la Comédie-Française*: 404. Same consequence.
- *The Art of the Theatre* (1924/25): no accessible full text under her name found; the p. 171 quote stays [R].
- *My Double Life*, chapter 33: fetches truncated before it; the "Life is short" line stays [R].
- Argentine newspaper archives (La Nación, La Prensa), 1886-87: not consulted. The named next step for the Buenos Aires gap.
- Trove (Australian digitised press), 1891-93 Australasian dates: not consulted.
- `marcel_proust.journey.json` and `captain_alfred_dreyfus.journey.json`: grepped, no Bernhardt match in either. Her Dreyfusard alignment rests on the dossier alone.
- Corpus-wide grep of 699 journey files: no mention of Sarah Bernhardt by name anywhere in the atlas before this file.
