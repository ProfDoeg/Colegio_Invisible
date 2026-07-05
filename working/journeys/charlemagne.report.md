# Charlemagne — journey report

Traveler: Charlemagne (Karolus Magnus), 742–814, the tomb kept open to 1215.
Register: national mythology — the canon is true. Calendar: Julian.
8 segments, 68 stops (target 50–70: met). Researcher's narrative report was cut off before landing; this file opens with the verification pass.

## Verification (2026-07-05)

Verifier pass over `charlemagne.journey.json`, repairs made in place, file re-validated with python after repair (68 stops, zero structural problems).

### 1. Structure / schema
- JSON parses. Top-level keys (`calendar, register, segments, title, traveler, years`) and per-stop keys (`name, lat, lng, date, date_confidence, campa, quote, quote_source, suggested_refs, sources`) match `joan_of_arc.journey.json` exactly. Segment shape (`name, stops`) matches. quote/quote_source null-pairing consistent on every stop.

### 2. Chronology and confidence honesty
- All 68 dates in strict chronological order, `0742-04-02` → `1215-07-27`. One date corrected: **Rome, Saint Peter's (the steps)** moved `0774-04-01` → `0774-04-02` — Julian Easter 774 fell on 3 April; the Liber Pontificalis puts the step-kissing on Holy Saturday, 2 April, which is what the campa already narrates.
- Confidence downgrades `attested` → `inferred` on 11 stops whose season/month is in the annals but whose day-date is the researcher's: Paderborn 777, Regensburg 791, Fossa Carolina 793, Frankfurt synod 794, Paderborn 799 (Leo's arrival), Portovenere 801, Vercelli 801, the missi of 802, the water-clock 807, the elephant's death 810, the Mainz bridge fire 813.
- Confidence `attested` → `traditional` on the five Chanson episodes at Roncevaux (the horn refused, the Oliphant, Durendal, Roland's death, the emperor's return). The day itself — 15 August 778 — is a true anchor (Eggihard's epitaph) and the ambush stop keeps `attested`; the episodes are the Chanson's and are now marked as the myth they are. **They stay.** Likewise kept, marked traditional: the seated emperor in the vault, Otto III's opening at Pentecost 1000 (19 May — computus checks out).
- Real anchors verified and left attested: Saint-Denis 28 Jul 754; Pepin's death 24 Sep 768; Noyon 9 Oct 768; Carloman's death 4 Dec 771; Christmas at the Eresburg 784; Mentana 23 Nov and the oath 23 Dec and the coronation 25 Dec 800; the elephant delivered 20 Jul 802 (RFA gives the day); Divisio Regnorum 6 Feb 806; Pippin's death 8 Jul 810; Charles the Younger 4 Dec 811; Louis crowned 11 Sep 813; death 28 Jan 814; canonization 29 Dec 1165; the last nail 27 Jul 1215.
- Final distribution: 21 attested / 28 inferred / 19 traditional.

### 3. Coordinates (web-spot-checked 20+ stops against Wikipedia geodata)
- Confirmed within tolerance: Basilica of Saint-Denis, Noyon, Corbeny, Worms, Eresburg/Obermarsberg, Geneva, Pavia, Verona, St Peter's Rome, Ibañeta/Roncevaux pass (43.020, −1.324; the five battle stops sit correctly along the pass), Pamplona, Zaragoza, Blaye, Verden an der Aller, Attigny, Ingelheim, Aachen chapel/throne (50.7748, 6.0839), Mentana, Portovenere (file points at the harbor tip by San Pietro — correct for a landing), Vercelli, Thionville, Milan, Lippeham/Wesel, Mainz, Chasseneuil-du-Poitou, Fronsac, Herstal.
- **Fixed:** Fossa Carolina — file had (49.028, 10.928), ~5 km off; the Karlsgraben at Graben near Treuchtlingen is (48.984, 10.921). Samoussy — file had (49.593, 3.717); village is (49.586, 3.735).

### 4. Quotes (checked against Fordham's Turner text of Einhard, the Oxford Roland, RFA/Scholz, Liber Pontificalis)
- Verbatim-confirmed: the tablets under the pillow (VK 25), the coronation protest (VK 28), the Avar hoard (VK 13), the swimming king (VK 22), the basilica of brass (VK 26), the death sentence with hour and years (VK 30), the epitaph Latin (VK 31), the Irminsul and the noon spring (RFA 772), Verden's 4,500 in one day (RFA 782), Widukind at Attigny (RFA 785), Vercelli winter and "The name of the elephant was Abul Abaz" (RFA 801/802), the water-clock (RFA 807), the acclamation Latin (Lib. Pont., Leo III), the Clausula of 767. All six Chanson quotes collated against the Oxford manuscript text (laisses 83, 133–134, 172, 174, 177, 267) — Old French verbatim, only editorial punctuation variance.
- **Restored to verbatim Turner (were paraphrase blends):** VK 9 the Roncevaux dead ("Eggihard, the King's steward; Anselm, Count Palatine; and Roland, Governor of the March of Brittany…"); VK 32 the fireball ("…his cloak buckle was broken and his sword belt shattered" — the file had conflated the two); VK 19 the tears for his children ("When his sons and his daughter died, he was not so calm…"); VK 32 the PRINCEPS omen tail ("But Charles despised, or affected to despise, all these omens, as having no reference whatever to him"); VK 32 bridge quote's "Mainz" restored to Turner's "Mayence". No quote had to be nulled — every attribution held.

### 5. Campa voice
- All 68 campas present tense, now 60–110 words (one trimmed: the self-crowning of Louis, 114 → 107, cutting a redundant clause, keeping the reliquary image). The great episodes read hot, not flat — the Oliphant bursting Roland's temples, Verden's axes heard in the chronicle's silence, the age turning at the third acclamation, the emperor seated in the dark with the Gospel open at the place where he stopped reading, Frederick II driving the last nail.

### 6. Stop count
- 68 stops within the 50–70 target; canon coverage is full (cradle to shrine, all major campaigns, the elephant, the omens, the open tomb). No additions needed.

### Myth kept intact
Nothing debunked. The Chanson's Roncevaux stands entire; the seated emperor holds his audience beneath the octagon; the time-folds are carried by `date_confidence`, exactly as the register demands.
