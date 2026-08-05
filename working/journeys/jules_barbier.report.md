# Jules Barbier (1825-1901): research report

*Atlas of Journeys, working/journeys. Compiled 2026-08. Subject: Paul Jules Barbier, French dramatist and librettist; with Michel Carré, supplier of texts to Gounod, Thomas, Offenbach, Saint-Saëns, Massé and Delibes.*

Legend. [A] = attested, source named. [R] = reconstruction, tradition, or general reference knowledge not re-verified against a fetched source this session. Contradictions are printed as contradictions and left standing.

---

## 0. A file-naming problem to resolve before anything else

**The most important finding in the dossier is not about Barbier's life.**

`paul_barbier.journey.json`, already in `working/journeys`, **is** the Jules Barbier journey. [A, direct read] Its `traveler` reads "Paul Jules Barbier"; its `title` reads "The Journey of Jules Barbier: Paris and the Myths Made Song"; its `years` are 1825-1901; its twenty-seven stops are the librettist's, from the Carré partnership through *Faust* (1859), *Mignon* (1866), *Les Contes d'Hoffmann* (1881) and *Françoise de Rimini* (1882).

`QUEUE.md` (lines 35-37) says `paul_barbier` is a *different, already-completed* person from Jules Barbier the librettist. **The queue note and the file contradict each other, and the file wins on evidence.** [A] Three outcomes are possible and this report chooses none: the file is mislabelled and should be renamed; or a separate Paul Barbier exists and that file was written against the wrong subject; or both stand and the atlas carries one man twice under two slugs.

**Recommendation: do not rebuild the globe with both files present until Anthony rules.** The artifacts here are a fresh `jules_barbier` pair drawn from the verified pool rather than from `paul_barbier.journey.json`, so a clean independently sourced text survives either ruling.

A separate confusion is already handled correctly: `barbier.journey.json` is Charles Barbier de la Serre, forerunner of braille, and never names Jules Barbier. [A, direct read]

---

## 1. Birth and household (1825 to c. 1840)

Birth. Paris, rue Marie-Éléonore-de-Bellefond, 9th arrondissement, number 7. [A, fr.wikipedia] **Contradiction, unresolved**: French Wikipedia gives **9 March 1825**, English Wikipedia **8 March 1825**, and neither cites a register. The journey carries 1825-03-09 with the discrepancy in `date_confidence`. [A / A, contradictory]

Father. Nicolas Alexandre Barbier (1789-1864), painter, drawing professor, private secretary to the Duc d'Aumale; some canvases bought by Louis-Philippe I. Jules is a first cousin of the poet Auguste Barbier (1805-1882). [A, fr.wikipedia]

**Lise Cristiani: a relationship the sources do not agree on.** The pool's chronology lens carried this at [A] ("a niece of the same age"), an overstatement downgraded here to [R]. fr.wikipedia "Jules Barbier" says "sa nièce du même âge". fr.wikipedia "Lise Cristiani" says she was born Agathe Barbier, an illegitimate child raised by her grandmother whose *second husband* was Jules's father, and that Jules "considers her as his sister"; her dates are 4 December 1825 to 14 October 1853, so she was nine months *younger*, and she died at Novotcherkassk, Russia. Two articles in one encyclopedia call the same woman a niece and a quasi-sister. **The journey states the relationship as disputed and names both readings.** She is independently notable as the first professional woman cellist in France and Europe. [A]

Gap. No reachable source gives Barbier's schooling, his mother's name, or any household address after the birth street. The geography lens's "Barbier family household" stop is the birth address reused, marked as such.

---

## 2. First stages and the Carré partnership (1848 to 1858)

- 1848: *Amour et Bergerie* at the Théâtre-Français (Palais-Royal). [A, fr.wikipedia] Year only: no month, cast, or notice found. **Gap.**
- 1851: with Michel Carré, *Les Contes fantastiques d'Hoffmann* at the Théâtre de l'Odéon, from E.T.A. Hoffmann's tales. [A, en.wikipedia; fr.wikipedia] The text Offenbach asks for thirty years later.
- 1852: *Galathée* for Victor Massé, among the earliest Barbier-Carré operatic collaborations. [A, en.wikipedia "Michel Carré"]
- 1858: *Le Médecin malgré lui*, after Molière, for Gounod. [A, fr.wikipedia] Day and venue not given in this pool. `paul_barbier.journey.json` asserts 15 January 1858 at the Théâtre-Lyrique, unconfirmed here and not carried over.

Coordinate correction, Odéon. The afterlife lens gave 48.8462 / 2.339; fr.wikipedia gives 48.8494 / 2.3386 and the geography lens 48.8499 / 2.3388, so the afterlife value is roughly 360 m too far south. The journey uses 48.8499 / 2.3388. [A]

---

## 3. Faust and the Second Empire years (1859 to 1865)

Faust. Premiere **19 March 1859**, Théâtre Lyrique, original version with spoken dialogue, after Carré's play *Faust et Marguerite* and loosely after Goethe's *Faust, Part One*. [A, en.wikipedia] The company was housed in the **Théâtre Historique, 72 boulevard du Temple**, from 27 September 1851 to 31 May 1862, so that is the correct 1859 house, at 48.8677 / 2.3649. [A, en.wikipedia "Théâtre Lyrique"]

Two pool claims deleted as false. The geography lens asserted *Faust* "is a commercial failure at first"; en.wikipedia says the opposite, "After a successful initial run at the Théâtre Lyrique" the publisher Choudens took the work on tour. The same lens's "most performed work in the nineteenth-century French repertoire" is narrowed to what the source supports: after the 1869 revision it became the most frequently performed opera *at the Paris Opéra*. [A]

- 1860: *La Colombe*, one act, at the **Theater der Stadt, Baden-Baden, 3 August 1860**, played four times; the Paris version follows at the Opéra-Comique on **7 June 1866**. [A, en.wikipedia] The pool's "Baden-Baden or Paris" hedge is removed. This is **the only stop outside France in the itinerary**, and no source says Barbier attended.
- 1860: *Philémon et Baucis*, Gounod, Théâtre-Lyrique. [R, not re-verified] `paul_barbier.journey.json` gives 18 February 1860; unconfirmed here, so the journey carries the year only.
- 1862: *La Reine de Saba*, Gounod, day not given. [A, fr.wikipedia] **12 August 1865**: Chevalier de la Légion d'honneur. [A, fr.wikipedia]

---

## 4. Goethe and Shakespeare made song (1866 to 1869)

- **17 November 1866**: *Mignon*, Thomas, after Goethe's *Wilhelm Meisters Lehrjahre*, Opéra-Comique (2nd Salle Favart); over 100 performances within a year. [A, en.wikipedia "Mignon"]
  - Arithmetic error corrected. The geography lens said the hall burned in 1887, "sixteen years before it is rebuilt". en.wikipedia "Salle Favart": destroyed by fire 25 May 1887, the third hall built 1893-1898 and opening 1898. That is **eleven** years. [A] The source's coordinate, 48.8709 / 2.3378, sits 22 m from the pool's 48.8711 / 2.3378; the journey keeps the pool value and the difference is recorded here.
- **27 April 1867**: *Roméo et Juliette*, Gounod, after Shakespeare, Théâtre-Lyrique Impérial du Châtelet, timed to the Exposition Universelle. [A, en.wikipedia]
- **9 March 1868**: *Hamlet*, Thomas, after Shakespeare, Paris Opéra, Salle Le Peletier, Jean-Baptiste Faure as Hamlet and Christine Nilsson as Ophélie. [A, en.wikipedia]
- 1869: *Faust* revised into grand-opera form for the Paris Opéra: recitatives replace the spoken dialogue, a ballet is added to the final act. [A, en.wikipedia]

---

## 5. Carré's death and the years alone (1872 to 1880)

Michel Carré dies at Argenteuil. A **date contradiction inside the corpus**: the chronology lens gives 27 June 1872 (en.wikipedia "Michel Carré"), `paul_barbier.journey.json` carries 28 June 1872. Not resolved; the journey uses 1872-06-27 with the alternative in `date_confidence`. [A / A, contradictory] Sources below are fr.wikipedia "Jules Barbier" unless another is named.

- 1873: *Jeanne d'Arc*, Barbier's own drama with incidental music by Gounod, Théâtre de la Gaîté. [A] Which building on the Gaîté's shifting footprint is not confirmed. **Gap.**
- 1876: *Paul et Virginie*, Massé, Carré still credited four years dead. [A, en.wikipedia] Old drafts, or a house attribution? No source found says. **Gap.**
- **14 June 1876**: *Sylvia, ou la nymphe de Diane*, scenario by Barbier and the Baron de Reinach, music by Delibes, Palais Garnier, Rita Sangalli dancing, Louis Mérante choreographing. [A, en.wikipedia]
- **23 February 1877**: *Le Timbre d'argent*, Saint-Saëns (completed 1865), at the Gaîté under Vizentini's Théâtre National Lyrique, conducted by Jules Danbé, after delays from finances and the war. [A, en.wikipedia]
- 1878: *Polyeucte*, Gounod, after Corneille. [A, year only]; the date 7 October 1878 and the Palais Garnier venue are [R, not re-verified].
- **17 May 1880**: birth of the son who becomes the actor Jean d'Yd (1880-1964), by the singer Berthe Perret. [A] **Coordinate corrected**: the geography lens pinned this at 48.8781 / 2.3459, *Barbier's own birth address*; fr.wikipedia gives the 10th arrondissement, and with no street the journey uses an approximate centre and says so.
- **13 July 1880**: Officier de la Légion d'honneur. [A] His other son, Pierre Barbier (1854-1918), becomes a librettist in turn [A]; Pierre's mother is unnamed everywhere reached. **Gap.**

---

## 6. Les Contes d'Hoffmann (1879 to 1882)

- **18 May 1879**: abridged private presentation at Offenbach's residence, with preliminary performers. [A, en.wikipedia] The address is not in the pool, so the journey uses the canonical Paris pin and says so.
- **5 October 1880**: Offenbach dies, four months before the premiere, leaving the piano score complete and the orchestration unfinished. [A]
- **10 February 1881**: premiere at the Opéra-Comique. Libretto by Barbier alone, from the 1851 Odéon play. Ernest Guiraud completes the orchestration. The Giulietta act is cut, though not simply cut: part of its music was redistributed to the Antonia act and the epilogue. [A]
  - Legend flagged and dropped. The geography lens stated Offenbach "died with the manuscript in his hand". The cited page does not support this; it is a deathbed topos this register must not launder into fact. **Removed.**
- 1882: *Françoise de Rimini*, Thomas, credited to Barbier **and Carré**, a decade after Carré's death. [R, en.wikipedia, cross-checked against the 1872 death date] The extent of Carré's real involvement versus early drafts is unresolved everywhere, and the journey says so.

---

## 7. Last years (1884 to 1901)

Sources below are fr.wikipedia unless another is named.

- 1884: candidate for the Académie française [A]; the candidacy **fails** [R]. No consulted source names who was elected instead or gives the vote. **Gap, stated as a gap.**
- 1890: *Jeanne d'Arc* revived with Sarah Bernhardt. The pool carried this at [R]; **upgraded to [A]** by fr.wikipedia "Sarah Bernhardt", which records her injured in 1890 "lors d'une représentation du Procès de Jeanne d'Arc au théâtre de la Porte-Saint-Martin". Coordinate corrected to 18 boulevard Saint-Martin, 48.8692 / 2.3567, 215 m from the pool's 48.871 / 2.3557. **Claim deleted**: the pool called this "his own oldest surviving dramatic text". False; *Amour et Bergerie* (1848) predates it by twenty-five years.
- **1890s**: an active Dreyfusard. [A] No specific act, signature, or publication is named. Gap; the journey invents none.
- **16 January 1901**: dies in the **3rd arrondissement**, aged 75. [A, both encyclopedias] No street address; the coordinate is the arrondissement's approximate centre, labelled so.
- 1901: first buried at the Cimetière de Passy. [A] **Coordinate corrected**: the afterlife lens gave 48.8637 / 2.2825, fr.wikipedia gives 48.8625 / 2.2853, and the pool value sits 240 m away, outside a cemetery of roughly a hectare.
- **Later**: remains transferred to the Cimetière ancien de Châtenay-Malabry, 107 avenue de la Division-Leclerc, 48.7619 / 2.2814; the tomb reads "Famille Jules et Marie Barbier". [A] Date of transfer unknown, so the journey files the stop at the year of death and says so. Marie Barbier is named only by that inscription. **Gap.**
- **Claim deleted**: the pool listed Sully Prudhomme among the cemetery's dead. He died at Châtenay-Malabry on 6 September 1907 and is buried at Père-Lachaise, 44th division. [A] Its actual notable dead include Paul Léautaud, Emmanuel Mounier, Jean Fautrier and Henri de Latouche.

---

## 8. A claim this report recommends dropping entirely

The afterlife lens carried, at [A], a commemorative plaque to Barbier at the église Notre-Dame-des-Otages, Paris. First, the coordinate is wrong: fr.wikipedia gives the church at 81 rue Haxo, 20th arrondissement, 48.8742 / 2.4031, about 950 m from the pool's 48.8657 / 2.4013. Second, and worse, **the claim is probably a name collision**: that church was built in 1938 to designs by the architect Julien Barbier, its own article says nothing about a plaque to Jules Barbier, and Jules Barbier died in 1901, thirty-seven years before the building existed. The claim rests on a photograph caption on the fr.wikipedia "Jules Barbier" page. The plaque is omitted from the journey and recorded here as unverifiable until someone reads the inscription.

---

## 9. Afterlife of the works

- ***Faust* abroad**: in Italian at La Scala, 1862, and Her Majesty's Theatre, London, 1863; German productions from 1861 sometimes retitle it *Margarethe* or *Gretchen*, shifting emphasis from the legend to Marguerite. [A, en.wikipedia]
- 1864: a new aria composed to English words by Henry Chorley, then translated into French as "Avant de quitter ces lieux". [A]
- ***Les Contes d'Hoffmann*, editions**: Gunsbourg (1904) and Choudens (1907) add material including "Scintille, diamant". [A] No single authoritative text circulates for decades.
- **The Saint-Mandé manuscripts**: Antonio de Almeida locates roughly **1,250 pages** in the **1970s**, at the house of an heir of one of Offenbach's daughters: vocal scores, libretto fragments, Guiraud's orchestration of the Venice act. [A, en.wikipedia] The pool recorded "no year given"; not a gap, the source says the 1970s. It feeds Oeser (1976) and Kaye (1988), and in 2011 the Kaye-Keck edition restores what is presented as Offenbach's original conception, one soprano heroine and one baritone villain across the acts. [A]

---

## 10. Quotations: what the pool actually holds

Barbier left **no reachable first-person text**: not a letter, not a preface, not an interview. Everything quotable is either his libretto verse or other people writing about him, and the journey's `quote` fields say which. Ten of the forty-three stops carry one, from Project Gutenberg 45806 (*Faust*, Oliver Ditson Co., 1906, with a prefatory note supplying two period judgments) and 15915 (*Les Contes d'Hoffmann*, Charles E. Burden, New York, 1907).

Two corrections to the pool's quote records. First, **Olympia's Doll Song is in Act II, not Act I**: the Burden edition is an "OPERA IN FOUR ACTS" whose Act I is the tavern prologue, its argument reads "ACT II. OLYMPIA." (line 132), "ACTE II" stands at line 3974, and the song at line 4287 falls before "TROISIEME ACTE." at line 4801. The wording is verbatim, including the source's own unaccented "Tout parle a la jeune fille". [A] Second, **the Muse's epilogue quote drops two diacritics** the source prints, "fidèle" and "rêve"; placement is correct, lines 6574-6577. [A] The journey prints the corrected text.

One quote is carried with a caution: the students' chorus, "Drig, drig, drig, master Luther", was rendered by the tool that read the file and could not be cross-checked line by line. [R] Not used as Barbier's words: the fr.wikipedia summary sentence beginning "Auteur de la plupart des livrets des opéras de Charles Gounod", quoted once and labelled as encyclopedic description.

---

## 11. Where this journey touches other atlas travelers

Named in `campa` where the paths genuinely cross:

- **goethe_full** [A]: names Barbier directly, on Mignon, "the very Italy of his own longing, which one day Barbier and Thomas will lift into opera". **Pin discrepancy flagged**: `paul_barbier` pins its Goethe-facing stop at 51.4809 / 11.972, `goethe_full` places Weimar at 50.98 / 11.329, roughly 65 km away. This journey inherits goethe_full's value, the canonical pin being the one in the subject's own file.
- **johann_faust** [A]: a Paris stop at the canonical 48.8566 / 2.3522 whose campa already says "Three centuries later Charles Gounod's Faust opens in this city and runs for decades". The gaze is mutual.
- **sheba**, **solomon** [R]: *La Reine de Saba* (1862) dramatizes the legend both carry, keyed to the canonical Temple Mount pin 31.778 / 35.2354, inherited byte for byte. Neither names Gounod or Barbier: thematic, not textual.
- **joan_of_arc** [R]: *Jeanne d'Arc* (1873, revived 1890) dramatizes that file's subject, which does not mention him. Domrémy pin inherited: 48.4436 / 5.6748.
- **dante** [A for both texts, R for the link]: *Françoise de Rimini* (1882) stages the Paolo and Francesca episode of *Inferno* V, which `dante` covers in a dedicated stop. Its Inferno stops sit at 31.7784 / 35.2298, a Jerusalem coordinate reflecting the poem's cosmology; not borrowed, the premiere having happened in Paris.
- **maurice_sendak**, **hans_christian_andersen** [R]: Sendak pulled *The Nutcracker* "back toward Hoffmann's harder story"; Andersen's first prose success was "in the manner of Hoffmann". Same German fantasist, no direct contact.
- **barbier** [A]: Charles Barbier de la Serre, no relation, named here and not in the journey precisely because there is nothing to name. **paul_barbier**: the duplicate of section 0.

Argenteuil (48.9472 / 2.2467), where Carré dies, appears to be a node not otherwise pinned here.

The shape of the itinerary. Across fifty years of libretti set in Goethe's Germany, Shakespeare's Verona, Solomon's Jerusalem, Dante's Rimini and Hoffmann's Nuremberg, **Barbier himself does not appear in any consulted source to have left Paris.** Every attested stop is a Paris address, theatre or cemetery, or one of two Paris suburbs. The one exception is *La Colombe* at Baden-Baden in August 1860, and no source says he attended it. Recorded as [R] and as a gap, not a confirmed negative: absence of travel evidence in two Wikipedia articles is not evidence of absence of travel. But it is the shape the reachable record has, and the journey is built to it rather than filled out with invented movement.

---

## Sources

Reached and used. fr.wikipedia "Jules Barbier" is the spine of the biography: birth street, father, Auguste Barbier, Lise Cristiani, the early plays, four Gounod titles, both Legion of Honour dates, the 1884 candidacy, Pierre Barbier, Jean d'Yd, the Dreyfusard note, death, Passy, Châtenay-Malabry. Also en.wikipedia "Jules Barbier", "Michel Carré", "Faust (opera)", "Théâtre Lyrique", "Mignon", "Salle Favart", "Hamlet (opera)", "Roméo et Juliette (opera)", "La colombe", "Le timbre d'argent", "Sylvia (ballet)", "The Tales of Hoffmann"; and fr.wikipedia "Lise Cristiani", "Sarah Bernhardt", "Jean d'Yd", "Cimetière de Passy", "Cimetière ancien de Châtenay-Malabry", "Église Notre-Dame-des-Otages", "Sully Prudhomme", "Théâtre de l'Odéon". Full texts read: Project Gutenberg 45806 (*Faust*, Ditson, 1906) and 15915 (*Les Contes d'Hoffmann*, Burden, 1907). Corpus files read: `paul_barbier`, `barbier`, `goethe_full`, `johann_faust`, `dante`, `joan_of_arc`, `solomon`, `sheba`, `maurice_sendak`, `hans_christian_andersen`, `QUEUE.md`.

Not reached, and why. No archival or state-record source was consulted: the birth-date contradiction could be settled by the Paris état civil registers for the 9th arrondissement, 1825, not fetched, and until they are it stands. **No French-language scholarly monograph on Barbier was located**, so everything biographical here descends from two Wikipedia articles that do not cite their own sources for the family details. That is thin ground for a fifty-year career, and it is said plainly rather than dressed up. The Académie française's 1884 registers would close section 7's gap; the Notre-Dame-des-Otages plaque was not read, so section 8 stands; Carré's posthumous credits would need the Opéra's or the publishers' contracts; Marie Barbier and Pierre Barbier's mother are unnamed in everything reached.
