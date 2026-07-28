#!/usr/bin/env python3
"""Localize the years strings in es/*.journey.json (passed through untranslated
by the merge). Exact-string map, applied once; any years string with letters
left unmapped and untouched is reported."""
import json, glob, os

HERE = os.path.dirname(os.path.abspath(__file__))
ES = os.path.join(os.path.dirname(HERE), 'es')

MAP = {
    # Memory cluster + classical spine + Cicero, 2026-07-22
    '106-43 BC': '106-43 a. C.',
    '356-323 BC': '356-323 a. C.',
    '384-322 BC': '384-322 a. C.',
    'c. 428-347 BC': 'c. 428-347 a. C.',
    '1265-1321': '1265-1321',
    'c.1214-1292': 'c. 1214-1292',
    '1561-1626': '1561-1626',
    '1548-1600': '1548-1600',
    '1668-1744': '1668-1744',
    '1138-1204': '1138-1204',
    '1552-1610': '1552-1610',
    '1232-1316': '1232-1316',
    'c. 1480-1544 (the Idea del Theatro printed, 1550)':
        'c. 1480-1544 (la Idea del Theatro impresa, 1550)',

    # Muslim/Sufi/Syria-Argentina fleet, 2026-07-20
    'c. AD 614-678': 'c. 614-678 d. C.',
    'c. 1145-1221': 'c. 1145-1221',
    'c. 858-922': 'c. 858-922',
    'c. 717-801': 'c. 717-801',
    'c. 789-857': 'c. 789-857',
    'c. 1813–1638 BC': 'c. 1813–1638 a. C.',
    'c. 1184-1177 BC (traditional; the fall of Troy to the founding of the Roman line)':
        'c. 1184-1177 a. C. (tradicional; de la caída de Troya a la fundación de la estirpe romana)',
    "c. 290-308 (traditional; birth to martyrdom, with her legend's afterlife reaching to 1431 and beyond)":
        'c. 290-308 (tradicional; del nacimiento al martirio, con la vida póstuma de su leyenda llegando a 1431 y más allá)',
    '742-814 (the tomb kept open to 1215)': '742-814 (la tumba abierta hasta 1215)',
    'c. 688–741': 'c. 688–741',
    '1901-1986 (the temple dances again to 2018)': '1901-1986 (el templo danza de nuevo hasta 2018)',
    '1451-1506 (relics to 1899)': '1451-1506 (las reliquias hasta 1899)',
    '1485-1547 (bones to 1947)': '1485-1547 (los huesos hasta 1947)',
    'c. 600-530 BC': 'c. 600-530 a. C.',
    "c. 850-814 BC (historical/legendary reign); with the poets' fold of the Aeneas years, traditionally c. 1182-1180 BC":
        'c. 850-814 a. C. (reinado histórico/legendario); con el pliegue de los poetas sobre los años de Eneas, tradicionalmente c. 1182-1180 a. C.',
    'c. 645-703 (traditional; the war years c. 688-703 attested in broad outline)':
        'c. 645-703 (tradicional; los años de guerra c. 688-703 atestiguados a grandes rasgos)',
    "1892–1946 (the film's own resurrection to 1984)":
        '1892–1946 (la propia resurrección de la película hasta 1984)',
    'c. 1162-1227': 'c. 1162-1227',
    "c. 650–710 (the tomb's afterlife to 1446)": 'c. 650–710 (la vida póstuma de la tumba hasta 1446)',
    '247-183 BC': '247-183 a. C.',
    'c. 355 – 1429 CE': 'c. 355 – 1429 d. C.',
    'c. 4 BC – AD 33': 'c. 4 a. C. – 33 d. C.',
    'c. 1211-1268 (coda to 1456)': 'c. 1211-1268 (coda hasta 1456)',
    'c. 1534-1557': 'c. 1534-1557',
    'c. 47 – 1780 (five parallel lives, one voice)': 'c. 47 – 1780 (cinco vidas paralelas, una voz)',
    '1895 – (vanished 1945)': '1895 – (desaparecida en 1945)',
    'c. AD 10 – AD 72 (the relic disputes run to AD 1279)':
        'c. 10 – 72 d. C. (las disputas por las reliquias llegan hasta 1279)',
    'c. 1391–1271 BC': 'c. 1391–1271 a. C.',
    'AD 570–632': '570–632 d. C.',
    '1830–1904 (gregorian)': '1830–1904 (gregoriano)',
    '1769-1821 (the ashes return, 1840)': '1769-1821 (las cenizas regresan, 1840)',
    'AD 1141–1209': '1141–1209 d. C.',
    'c. 1487-1537 (coda to 1937)': 'c. 1487-1537 (coda hasta 1937)',
    'c. 1160-1226 (the two endings)': 'c. 1160-1226 (los dos finales)',
    'c. 1170-1226': 'c. 1170-1226',
    '1478-1541 (the bones to 1985)': '1478-1541 (los huesos hasta 1985)',
    'c. 287-306 AD (coda to 1893)': 'c. 287-306 d. C. (coda hasta 1893)',
    'c. 966 BC (traditional)': 'c. 966 a. C. (tradicional)',
    'c. 970-931 BC (traditional/inferred)': 'c. 970-931 a. C. (tradicional/inferido)',
    'c. 1184–1174 BC': 'c. 1184–1174 a. C.',
    'c. 1640–1661 (coda to 1736)': 'c. 1640–1661 (coda hasta 1736)',
    'c. 628-551 BC': 'c. 628-551 a. C.',
    'c. AD 495-1191 (a legendary lifetime, closed by the historical rediscovery of her grave)':
        'c. 495-1191 d. C. (una vida legendaria, cerrada por el redescubrimiento histórico de su tumba)',
    "c. 755-848 (Greub's redating; conventional chronicles close the life in 812 or 814)":
        'c. 755-848 (la redatación de Greub; las crónicas convencionales cierran la vida en 812 u 814)',
    "c. 500-537 (traditional Arthurian chronology; the reign of Arthur, from Merlin's love to the barge at Camlann)":
        'c. 500-537 (cronología artúrica tradicional; el reinado de Arturo, del amor de Merlín a la barca de Camlann)',
    'c. 502-543 (traditional Arthurian chronology; Camlann fixed, with this atlas, at 537)':
        'c. 502-543 (cronología artúrica tradicional; Camlann fijada, con este atlas, en 537)',
    "c. 450-c. 577 (traditional; Geoffrey of Monmouth's own conflation of the two Merlins)":
        'c. 450-c. 577 (tradicional; la propia fusión de los dos Merlines por Godofredo de Monmouth)',
    'c. 460-1211 (traditional Arthurian era, through the Norman-Sicilian and Grail-romance reception)':
        'c. 460-1211 (era artúrica tradicional, a través de la recepción normando-siciliana y de los romances del Grial)',
    "826-848 (Werner Greub's chronology: Wolfram's Parzival read as ninth-century history)":
        '826-848 (la cronología de Werner Greub: el Parzival de Wolfram leído como historia del siglo nueve)',
}

changed = unmapped = 0
for f in sorted(glob.glob(os.path.join(ES, '*.journey.json'))):
    j = json.load(open(f))
    y = j.get('years', '')
    if y in MAP:
        if MAP[y] != y:
            j['years'] = MAP[y]
            with open(f, 'w') as out:
                json.dump(j, out, ensure_ascii=False, indent=1)
            changed += 1
    elif any(c.isalpha() for c in y):
        print('UNMAPPED:', os.path.basename(f), '|', y)
        unmapped += 1
print(f'{changed} years localized, {unmapped} unmapped')
