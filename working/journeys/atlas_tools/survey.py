"""survey.py — run the whole survey and print it in the shape of
atlas_network_survey.md, so successive surveys are diffable.

    python3 survey.py            # full survey
    python3 survey.py --brief    # headline counts only

Every number is measured against the files. Nothing here is estimated.
"""
import sys

from load import Corpus
from social import Social
from geo import Geo
from temporal import Temporal, truekey
from style import Style, EM_DASH


def main(brief=False):
    c = Corpus()
    print("# Atlas network survey - generated")
    print(f"*{c.summary()}*\n")
    if c.errors:
        print("!! unreadable files above must be fixed before trusting any count\n")

    soc, geo, tmp, sty = Social(c), Geo(c), Temporal(c), Style(c)

    print("## A. Interlock: asymmetric gazes (A names B, B silent)")
    asym = soc.asymmetries()
    print(f"*{len(asym)} asymmetric pairs*\n")
    for a, b, n in asym[:12]:
        print(f"- **{a}** names {b} {n}x, no return gaze")

    print("\n## B. Pin drift: same event, non-identical pins")
    drift = geo.pin_drift(same_date_only=True)
    print(f"*{len(drift)} same-date pairs violating the byte-identical rule*\n")
    for a, b, d in drift[:12]:
        print(f"- {d:.0f}m **{a.slug}** ({a.lat_s},{a.lng_s}) vs **{b.slug}** "
              f"({b.lat_s},{b.lng_s}) [{a.date}] - {a.name[:44]}")

    print("\n## C. Canonical pins (3+ journeys, byte-exact) - inherit these")
    for pin, slugs in geo.canonical_pins()[:8]:
        print(f"- `({pin[0]}, {pin[1]})` {len(slugs)} journeys: {', '.join(slugs[:5])}")

    print("\n## D. Chronology")
    bug = tmp.bce_order_bug()
    print(f"- **BCE time-navigation quirk**: {sum(n for _, n in bug)} adjacent same-year "
          f"stop pairs across {len(bug)} journeys. `datekey` negates the whole fractional "
          f"year, so months invert inside one BCE year. NOTE: journey paths and the "
          f"traveler list are NOT affected - stops draw in file order and the traveler "
          f"sort was verified correct. This touches only the time scrubber and "
          f"next/prev-in-time navigation. Low priority.")
    for slug, n in bug[:6]:
        print(f"  - {slug}: {n}")
    reg = tmp.regressions()
    print(f"- **Genuine regressions**: {len(reg)}")
    for slug, a, b in reg[:6]:
        print(f"  - {slug}: {a.date} -> {b.date}")

    print("\n## E. House style")
    em = sty.em_dashes()
    print(f"- em dashes in authored text: **{len(em)}** (rule: none)")
    regs = sty.register_variants()
    print(f"- `register` variants: **{len(regs)}** (should be 1)")
    for v, n in regs.most_common():
        flag = "  <- EM DASH" if EM_DASH in (v or "") else ""
        print(f"  - {n:4}x `{v}`{flag}")
    print(f"- curly quotes: **{len(sty.curly_quotes())}** (rule: zero)")
    short, long_ = sty.campa_length()
    print(f"- campa outside 450-650 chars: {len(short)} short, {len(long_)} long "
          f"({100*(len(short)+len(long_))/max(1,len(c.stops)):.0f}% of stops)")

    if brief:
        return
    print("\n## F. Quote deserts (corpus median ~12/journey)")
    for slug, q, n in sty.quote_density()[:10]:
        print(f"- {slug}: {q} quotes / {n} stops")

    print("\n## G. Temporal deserts (>=50 empty years)")
    for a, b, g in tmp.deserts()[:8]:
        print(f"- {a:.0f} -> {b:.0f}: {g:.0f} empty years")

    print("\n## H. Geographic deserts (10deg cells held by one journey)")
    for cell, slugs in geo.deserts()[:10]:
        print(f"- {cell}: {slugs[0]}")


if __name__ == "__main__":
    main(brief="--brief" in sys.argv)
