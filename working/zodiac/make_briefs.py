#!/usr/bin/env python3
"""Write the twelve per-sign briefs into working/zodiac/briefs/. Each brief is the
figure-specific half of the prompt; the shared half is PROMPT_TEMPLATE_ZODIAC.md."""
import os
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "briefs"); os.makedirs(OUT, exist_ok=True)

SIGNS = {
 "aries": ("Aries", "the Ram", "MUL.LU.HUN.GA, the Hired Man (Agrarian Worker) of Babylon, only later a ram; Ammon's ram at Thebes; the Golden Fleece of Phrixus and Helle and the Argonauts; the age of Aries and the vernal point (Hipparchus' first point of Aries, now in Pisces); Hamal, Sheratan, Mesarthim; Manilius' opening; the Lamb of God and Schiller's St Peter; Gad in the tribal schemes; the Hebrew letter He; alchemical calcination; Mars, exaltation of the Sun; the head; March-April; the Roman New Year"),
 "taurus": ("Taurus", "the Bull", "GU.AN.NA, the Bull of Heaven that Ishtar sends against Gilgamesh; the Egyptian Apis and Hathor; Zeus as the bull of Europa, Io; the Pleiades and Hyades inside it, Aldebaran the follower, the Crab Nebula and the supernova of 1054 recorded in China; Mithras slaying the bull as the precession of the equinox out of Taurus (Ulansey's thesis and its critics); the golden calf; Schiller's St Andrew; Venus, exaltation of the Moon; the neck; the bull-leapers of Knossos; Lascaux's bull-and-dots claim"),
 "gemini": ("Gemini", "the Twins", "MASH.TAB.BA.GAL.GAL, the Great Twins of Babylon (Lugalirra and Meslamtaea); Castor and Pollux, the Dioscuri, St Elmo's fire, the twin gods of sailors; Romulus and Remus, Amphion and Zethus, the Ashvins of the Vedas; Adam and Eve in Arab-Latin manuscripts; Schiller's St James the Great; the ecliptic's northernmost point and the summer solstice's drift; Mercury; the arms and hands; the Geminid meteors; the twin motif in alchemy (Rebis) and in the Tarot's Lovers"),
 "cancer": ("Cancer", "the Crab", "AL.LUL, the Babylonian crayfish; the crab sent by Hera against Heracles at Lerna; Praesepe, the Manger, with the two Asses (Asellus Borealis and Australis) and its role as a weather sign in Aratus and Pliny; the Tropic of Cancer and the summer solstice's departure from it; the gate of souls descending (Porphyry, De antro nympharum; Macrobius); the darkest sign, no bright star; Schiller's St John; the Moon; the breast; the Egyptian scarab in Dendera; Ptolemy's 'cloudy mass in the breast'"),
 "leo": ("Leo", "the Lion", "UR.GU.LA, the Great Lion of Babylon, and Regulus the King Star (Sharru, Basiliskos, Cor Leonis) as one of the four royal stars; the Nemean lion; the lion of the Sun, Sekhmet and the Egyptian summer; the Sickle; the Leonid meteors and 1833; Judah's lion; Schiller's St Thomas; the Sun's own house; the heart and back; Coma Berenices cut from its tail (Conon of Samos, Berenice's hair); the lion in alchemy (the green lion devouring the sun); Denderah's lion on a serpent"),
 "virgo": ("Virgo", "the Virgin", "AB.SIN, the Furrow, with Spica the ear of grain; the Babylonian Shala; Dike/Astraea leaving the earth (Aratus, Hesiod's ages), Erigone and Icarius, Demeter/Ceres, Isis with the wheat, Tyche; the autumnal equinox and the 'first point of Libra'; the Virgin Mary in Christian readings (the Nativity's Virgo rising arguments), Schiller's St James the Less; Mercury's house and exaltation; the belly; the Virgin Islands and the September harvest; the largest zodiac constellation; Vindemiatrix the grape-gatherer"),
 "libra": ("Libra", "the Scales", "ZIB.BA.AN.NA, the Balance of Heaven, in Babylon already a scale; in Greece the Claws of the Scorpion (Chelae) until the Romans, Julius Caesar's calendar and Augustus' reading of it; Zubenelgenubi and Zubeneschamali (the southern and northern claws); the only inanimate figure; Astraea's scales; Ma'at's feather and the weighing of the heart in Egypt; Schiller's St Philip; Venus's house, Saturn's exaltation; the kidneys and loins; the equinox and the balance of day and night; the Tarot's Justice"),
 "scorpio": ("Scorpius", "the Scorpion", "GIR.TAB of Babylon, guardians of the sun's gate in Gilgamesh (the scorpion-men at Mashu); Antares the rival of Mars, Isis' scorpion goddess Serqet, the scorpion that killed Orion (never in the sky together); the Claws lost to Libra; the Ophiuchus argument (the thirteenth sign of 1995 and 2011 and its history); Schiller's St Bartholomew; Mars and Pluto; the genitals; the eagle and the phoenix as its 'higher' forms in modern astrology (and the invented lineage of that idea); Dan in the tribal schemes; Maui's fishhook in Polynesia"),
 "sagittarius": ("Sagittarius", "the Archer", "PA.BIL.SAG of Babylon, the winged centaur-archer with a scorpion's tail, older than Chiron; Crotus the satyr son of Pan (Eratosthenes) versus Chiron (who is Centaurus); the Teapot, the Milky Way's center and the galactic core in it, Sagittarius A*; the winter solstice's arrival there; Schiller's St Matthew; Jupiter; the thighs; the Sumerian Nergal; the Ashvins' bow; the Sagittarius Dwarf; the 1970s 'Galactic Center' astrology and the 2012 alignment claim"),
 "capricorn": ("Capricornus", "the Goat-fish", "SUHUR.MASH, the goat-fish of Ea/Enki, the oldest continuously attested figure of the twelve; Pan fleeing Typhon into the Nile and becoming half fish (Hyginus); Amalthea the goat and the cornucopia; the Tropic of Capricorn and the winter solstice's departure; the gate of the gods ascending (Macrobius, Porphyry); Augustus' coin with the capricorn as his birth or conception sign (Suetonius); Schiller's St Simon; Saturn's house, Mars' exaltation; the knees; the Sea-goat in alchemy; the Christmas and Sol Invictus arguments"),
 "aquarius": ("Aquarius", "the Water-bearer", "GU.LA, the Great One, Ea pouring the two streams, the Babylonian rainy season; Ganymede as cup-bearer of Zeus, Deucalion, Cecrops; the water poured into Piscis Austrinus' mouth; the Egyptian Nile flood and Hapi; the 'Age of Aquarius' from its origins (the nineteenth-century precession astrologers, Jung's 1940 letter, Hair 1967) to the dispute over its date; Schiller's St Jude; Saturn's house and the modern Uranus; the shins; Sadalmelik and Sadalsuud, the lucky stars of the king; the Helix Nebula"),
 "pisces": ("Pisces", "the Fishes", "the Babylonian Tails (SIM.MAH and the Anunitum fish) and the cord; Aphrodite and Eros fleeing Typhon as fishes, or the fishes that carried the egg of Atargatis from the Euphrates (Hyginus), the Syrian fish taboo; the vernal point in Pisces since the second century BCE and the 'Age of Pisces' as the Christian age; the fish of the Christians (ichthys, the 153 fishes, the vesica) and the astrological readings of it; Alrescha the knot; Schiller's St Matthias; Jupiter's house and the modern Neptune, Venus' exaltation; the feet; the Circlet; Dürer's 1515 map"),
}

for slug, (name, epithet, pointers) in SIGNS.items():
    text = f"""# {name}: research brief

Zodiac research, Anthony 2026-09-12, separate from the atlas. Appended to
PROMPT_TEMPLATE_ZODIAC.md by atlas_tools/codex_dossier_zodiac.py.

---

FIGURE. {name}, {epithet}, one of the twelve figures of the zodiac. Treat the sign (the thirty-degree
band of the ecliptic) and the constellation (the star figure) as two things with one name, and keep
them distinct throughout; give the tropical and sidereal dates and the constellation's current
boundaries and brightest stars.

THREADS TO PULL, each to be verified against the sources and dated: {pointers}.

STANCE. Myth as fully as fact. Every claim labeled: documented fact, scholarly reconstruction,
tradition, disputed, legend, modern invention; the first appearance of each story, who spread it,
and what evidence exists. Popular astrology and its history are part of the record, not to be
sneered at and not to be asserted. Absence of evidence is a finding: say what could not be traced.
"""
    open(os.path.join(OUT, f"{slug}.brief.md"), "w").write(text)
    print("wrote", slug)
