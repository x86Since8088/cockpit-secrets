# DESIGN — cockpit-secrets

The visual and interaction specification. It is written so an implementer makes **no aesthetic
decision of their own**: every colour, size, spacing step, breakpoint and state has a value here,
and every judgement call is labelled as one with the trade written next to it.

Scope: `index.html`, `secrets.css`, a new `theme.js`, the rendering functions in `secrets.js`, and
the selector migrations the browser suites need. It changes no verb, no request shape, no helper
behaviour and no access check.

**Every number in this document was measured on this host or computed from measured values.**
Where something was not measured, it says so and says what to measure. Sources: the live browser
findings in `tests/browser/artifacts/` (probes 1–10), three further probes run for this design pass
(§0.1), and a contrast computation over the proposed palette (§2.6).

---

## 0 · The two sentences everything else follows from

**1. This is a security tool living inside someone else's application.** A page that invents its
own palette inside a host application reads as untrusted, and for a password manager looking
untrustworthy is a functional defect. So it follows Cockpit's theme, spacing, type and control
idiom. Every deviation below is deliberate, and each one has a measured number attached to it.

**2. Dangerous things must look dangerous and calm things must look calm.** Revealing a password,
exporting plaintext and deleting a safe are not the same weight as browsing a list; today they are
styled almost identically. §7 is the ladder that fixes that.

Nothing here relaxes anything. No inline `<style>`, no inline `<script>`, no `eval`, no WASM, no
CSP change (I9). No secret touches storage (I11). The only JS→CSS channel this design opens is
`element.style.setProperty("--sec-…", value)` for genuinely dynamic single numbers — the option the
brief prefers over string-built styles.

---

## 0.1 · What this design pass measured for itself

Three probes were run against the real Cockpit 360 at `https://localhost:9090`, signed in as
`cptestadm`, inside `iframe[name="cockpit1:localhost/secrets"]`. `cockpit.socket` was not touched.
The operator's `pwsafe3` safe was never listed, opened, read or photographed — it is registered only
in `~eddie/.config/cockpit-secrets/safes.d/`, and a user-class safe is read from the caller's own
home, so `cptestadm` cannot see it. No safe was unlocked. No file under the source root was written
except this document.

| # | Question | Answer |
|---|---|---|
| **P11** | Can the plugin frame read the shell's *resolved* theme out of the parent document, with no storage API at all? | **Yes.** §3. |
| **P12** | Do Cockpit's font files load from our package over the real CSP? | **Yes**, 200 on all five, `FontFace.status === "loaded"` on all five, 0 CSP violations. §2.7. |
| **P13** | Which font files does the shell *already* fetch, so what is the marginal cost? | It fetches the **variable** faces `RedHatTextVF.woff2` + `RedHatDisplayVF.woff2`, not the static per-weight files. §2.7. |

P11, verbatim (`scratchpad/probe11.json`): `window.parent` is readable from inside the frame
(`depth: 1`, `parent === top`, `sameDoc: true`), and the parent's `<html>` class mirrored the shell's
own in **every** state driven through the shell's real Session menu:

| Shell setting | Shell `<html>` class | What the frame read | `prefers-color-scheme` |
|---|---|---|---|
| Dark, OS light | `index-page pf-v6-theme-dark` | `parentDark: true` | `false` ← **the defect state** |
| Light, OS light | `index-page` | `parentDark: false` | `false` |
| Default (auto), OS light | `index-page` | `parentDark: false` | `false` |
| Light, OS **dark** | `index-page` | `parentDark: false` | `true` ← **the other defect state** |

A `MutationObserver` installed on the parent's `<html>` **from inside the frame** logged every one of
those transitions. `securitypolicyviolation` count: **0**. Opened standalone (no shell), the same
code reports `isFramed: false`, `topIsSelf: true`, `parentClass: ""` — cleanly detectable, so the
fallback branch is reachable and testable.

P13, verbatim: the shell requested `RedHatTextVF.woff2` and `RedHatDisplayVF.woff2`, and
`document.fonts` in the shell reports exactly one loaded family: **`Red Hat Text 400 500/normal`**.
Two consequences in §2.7.

---

## 1 · Layout — the shape of the page

### 1.1 One workspace, one pane

Today there are two unrelated layouts: a card grid on the safes view and a three-column
`.sec-split` on the browse view. The three-column layout **never happens** — measured:
`secrets.css:244` collapses it at `max-width: 75rem` (1200px), and Cockpit's iframe at a 1400px
window is only **1160px**, so the entry detail renders as a 208 × 1384 px strip below the fold with
900px of empty space beside the table (`artifacts/browse-detail-1400.png`). The reason the page
exists is unreadable at the default window size.

Both views become one grid with one right-docked pane (R3):

```
.sec-page
├── #sec-agent-banner        sticky, FULL WIDTH, above everything (I18)
├── .sec-topbar              title · #sec-sub · status chips · Refresh · Lock ·│· pane toggle
├── #sec-alerts  #sec-live  #sec-banners
├── #sec-workspace                       ← the grid
│   ├── #sec-main   (role=region)        ← the safes table, OR tree + entries table
│   └── #sec-pane   (aside, role=complementary, aria-label="Details")
└── .sec-footer
```

```css
#sec-workspace { display: grid; gap: var(--sec-s-3);
                 grid-template-columns: minmax(0, 1fr); align-items: start; }
@media (min-width: 60rem) {
    #sec-workspace.sec-pane-open { grid-template-columns: minmax(0, 1fr) var(--sec-pane-w); }
    #sec-pane { position: sticky; top: var(--sec-s-3); max-block-size: calc(100vh - 6rem);
                overflow: auto; }
}
```

**The pane is after `#sec-main` in the DOM in both layouts.** It is never visually reordered, so
the tab order and the reading order are the same thing at every width. That is the reason it stacks
*below* the table on narrow rather than above it — not laziness.

### 1.2 Breakpoints — measured against the frame, not the window

Cockpit's sidebar eats the width. Measured `document.documentElement.clientWidth` inside the frame:

| Window | 1400 | 1000 | 700 | 480 | 360 |
|---|---|---|---|---|---|
| **Frame** | **1160** | **760** | 700 | 480 | 360 |

Any `max-width`/`min-width` query in `secrets.css` evaluates against the frame. This is why
`75rem` was wrong: it can effectively never be met.

| Frame width | Pane | `--sec-pane-w` | Groups tree (browse) |
|---|---|---|---|
| **≥ 78rem** (1248px) | docked right | `28rem` | left column, `15rem` |
| **≥ 60rem** (960px) | docked right | `24rem` | left column, `13rem` |
| **< 60rem** | full-width panel **below** the table | — | disclosure above the table (§6.1) |

At the ordinary 1400px window the frame is 1160px = 72.5rem → **docked, 24rem**, leaving 728px for
the table. That is the defect fixed: 60rem is reachable where 75rem was not.

At the WCAG-200%-zoom viewport (700 × 480 CSS px, the correct way to test it) the frame is 700px
= 43.75rem → the pane un-docks, one column, no horizontal scroll. Today's page passes 1.4.10
(`scrollWidth 700 === clientWidth 700`); the new layout must keep that, and §11.5 gives the
assertion.

### 1.3 Pane open/closed defaults, and what "collapsed" means

- **Default at ≥ 60rem: open.** Default at < 60rem: **collapsed**.
- The default is recomputed only when the frame crosses 60rem, and only if the operator has not
  toggled the pane since the last crossing. One boolean, in memory.
- **Collapsed means gone. No sliver.** A sliver of a pane whose content includes a revealed value is
  a half-open door, and it costs horizontal space for no information. The affordance that the pane
  exists is the toggle button, which is always in the topbar and always carries `aria-expanded`.

**Do not persist any of this** — see §9.

---

## 2 · The token layer

### 2.1 The decision: copy the values, do not link the bundle

Measured: linking `../shell/shell.css` is CSP-legal and yields 970 custom properties in light /
1056 in dark, plus Red Hat Text. It costs **126 KB gzipped (1,309,372 B raw)**, it imports PF6's
element reset — `h1` 24→36px, `h2` 24→28px, `h3` 16.8→24px, `body` background `#ffffff`→`#f2f2f2`,
`box-sizing` `content-box`→`border-box` on every element measured — and it couples this page's
appearance to whatever PatternFly version the host's Cockpit happens to ship. There is no smaller
bundle: the cheapest token source on this host is `systemd/terminal.css.gz` at 75 KB gz, and every
one of them carries the whole PF6 component library.

We use roughly forty-five values. Copying them costs nothing and couples to nothing.
**So: our own `--sec-*` names, PF6's values, written down.**

`../../static/branding.css` is **not** linked either. Measured: 338 bytes, three rules, **zero**
custom properties, two id selectors (`#badge`, `#brand`) our markup does not use. It exists so the
shell's brand furniture has art. Rendering another product's brand mark on our page is precisely the
"this is not what it claims to be" failure this design exists to avoid.

*Snapshot warning, to be kept in the file as a comment:* the values below are PatternFly 6 as
shipped by Cockpit 360 on Ubuntu 26.04.1. They moved between PF5 and PF6 and will move again. They
are a **snapshot, not a contract**. When they drift, the page will look slightly dated, not broken —
which is the correct failure mode and is strictly better than a hard runtime dependency.

### 2.2 Colour tokens — the complete table

Light is the base on bare `:root`. Dark is redefined under **both** `:root.sec-dark` and the
`prefers-color-scheme` fallback (§3.3). Nothing is defined only inside a media query.

| Token | Light | Dark | Source | Used for |
|---|---|---|---|---|
| `--sec-canvas` | `#f2f2f2` | `#151515` | PF `background--color--secondary--default` | `body`; the ground everything sits on |
| `--sec-surface` | `#ffffff` | `#292929` | PF `background--color--primary--default` | table, panes, panels — elevation 1 |
| `--sec-raised` | `#ffffff` | `#383838` | PF `background--color--floating--default` | modal, un-docked pane — elevation 2 |
| `--sec-inset` | `#f2f2f2` | `#1f1f1f` | PF `background--color--control--read-only` (dark hand-picked, §2.6) | value wells, `.sec-code`, `.sec-readonly`, `.sec-pre`, `.sec-path` |
| `--sec-hover` | `#e9e9e9` | `#383838` | PF `background--color--secondary--hover` (light darkened, §2.6) | row and tree-item hover |
| `--sec-sel` | `#e7f1fd` | `#12314f` | ours — a tint of the accent | selected row background |
| `--sec-ink` | `#151515` | `#ffffff` | PF `text--color--regular` | all body text |
| `--sec-sub` | `#4d4d4d` | `#c7c7c7` | PF `text--color--subtle` | secondary text, `dt`, hints, captions |
| `--sec-disabled` | `#a3a3a3` | `#707070` | PF `text--color--disabled` | disabled control labels |
| `--sec-inverse` | `#ffffff` | `#1f1f1f` | PF `text--color--inverse` | text on a filled dark/light block |
| `--sec-accent` | `#0066cc` | `#92c5f9` | PF `border--color--brand--default` | primary fill, selected-row bar, meters, progress |
| `--sec-accent-ink` | `#ffffff` | `#1f1f1f` | PF `text--color--on-brand--default` | label **on** `--sec-accent` |
| `--sec-link` | `#0066cc` | `#b9dafc` | PF `text--color--brand--default` | link-styled buttons, `<summary>` |
| `--sec-focus` | `#0066cc` | `#92c5f9` | PF `focus-ring--color--default` | the focus ring, and **only** the focus ring |
| `--sec-line` | `#c7c7c7` | `#444548` | PF `border--color--default` (dark hand-picked) | **decorative** hairlines: row separators, section rules |
| `--sec-edge` | `#87898c` | `#a3a3a3` | **ours — a deliberate deviation, §2.5** | the boundary of an **interactive control**: button, input, select, pane edge |
| `--sec-ok` | `#3d7317` | `#87bb62` | PF `text--color--status--success--default` | success text and icons |
| `--sec-ok-bg` | `#e8f3de` | `#1e2a17` | ours | success tint |
| `--sec-ok-edge` | `#3d7317` | `#87bb62` | PF | success block border |
| `--sec-warn` | `#7a5300` | `#ffcc17` | **ours in light — deviation, §2.5**; PF in dark | warning text |
| `--sec-warn-bg` | `#fdf3d9` | `#2f2409` | ours | warning tint, agent banner |
| `--sec-warn-edge` | `#946800` | `#dca614` | ours light / PF dark | warning block border |
| `--sec-danger` | `#a30000` | `#f89b78` | ours light (PF `#b1380b` also passes) / PF dark | danger text, `.sec-btn.danger` label |
| `--sec-danger-bg` | `#fbe9e7` | `#3a1a12` | ours | danger tint, `.sec-danger-block` |
| `--sec-danger-edge` | `#a30000` | `#f0561d` | ours light / PF `color--status--danger--default` dark | danger block border |
| `--sec-info` | `#5e40be` | `#b6a6e9` | PF `text--color--status--info--default` | informational text |
| `--sec-info-bg` | `#eee9fb` | `#241d38` | ours | informational tint |

### 2.3 Type

Root stays 16px. **`body` gets `font-size: var(--sec-fs-body)` = 0.875rem**, which is Cockpit's own
body default. Every `rem` length elsewhere stays relative to the 16px root, which is what we want.

| Token | Value | px | PF source | Used for |
|---|---|---|---|---|
| `--sec-fs-sm` | `0.75rem` | 12 | `font--size--body--sm` | chips, badges, countdown numerals, table captions, `.sec-safe-id`. **This is the floor.** |
| `--sec-fs-body` | `0.875rem` | 14 | `font--size--body--default` | everything by default: cells, labels, buttons, hints, help text |
| `--sec-fs-lg` | `1rem` | 16 | `font--size--body--lg` | the value well (a revealed secret), lead sentences |
| `--sec-fs-h4` | `1rem` | 16 | `font--size--heading--h4` | `.sec-eyebrow`, detail section headings |
| `--sec-fs-h3` | `1.125rem` | 18 | `font--size--heading--h3` | pane heading, entry title, `.sec-state` heading |
| `--sec-fs-h2` | `1.25rem` | 20 | `font--size--heading--h2` | view headings, modal titles |
| `--sec-fs-h1` | `1.5rem` | 24 | `font--size--heading--h1` | "Secrets" |
| `--sec-lh-body` | `1.5` | — | `font--line-height--body` | body |
| `--sec-lh-heading` | `1.3` | — | `font--line-height--heading` | headings |
| `--sec-fw-normal` | `400` | — | `font--weight--body--default` | |
| `--sec-fw-med` | `500` | — | `font--weight--body--bold` | **the only emphasis weight**, see below |

**Why this matters.** Measured on the live safes list, the sizes actually rendering were
12.48px ×13, 12.80px ×3, **13.12px ×37**, 14.00px ×23, 14.40px ×3, 16.00px ×4, 16.80px ×2, 20px ×1,
24px ×2 — **53 of 88 text runs under 14px**, and the single most common size, 13.12px (`0.82rem`),
is *below* Cockpit's body default. The page reads as cramped because it is: it is smaller than its
host almost everywhere. The fix is one line — the ad-hoc `0.82rem` becomes `--sec-fs-body`, and only
chips, captions and countdown numerals drop to `--sec-fs-sm`.

**There is no bold.** `--pf-t--global--font--weight--body--bold` is **500**; PF6 labels 700 as
`--legacy`. And the variable face Cockpit ships declares `font-weight: 400 500` (measured: the shell's
`document.fonts` reports exactly `Red Hat Text 400 500/normal`), so asking for 700 gets a
*synthesised* faux bold, which is a smeared version of the same glyphs. Every `font-weight: 700` in
`secrets.css` becomes `var(--sec-fw-med)`. Headings may use `--sec-fw-med` too; nothing on this page
uses 700.

### 2.4 Space, radius, elevation

| Token | Value | PF source |
|---|---|---|
| `--sec-s-1` | `0.25rem` | `spacer--xs` |
| `--sec-s-2` | `0.5rem` | `spacer--sm` |
| `--sec-s-3` | `1rem` | `spacer--md` |
| `--sec-s-4` | `1.5rem` | `spacer--lg` |
| `--sec-s-5` | `2rem` | `spacer--xl` |
| `--sec-s-6` | `3rem` | `spacer--2xl` |

**Rule: no length in `secrets.css` may be a number that is not one of these six**, except border
widths, the countdown track height, and `--sec-pane-w`. Today the file uses
0.05/0.12/0.15/0.2/0.22/0.25/0.3/0.35/0.4/0.45/0.55/0.6/0.65/0.7/0.75/0.8/0.9/1.1/1.2 rem — nineteen
improvised steps, which is why nothing lines up with anything. Control padding comes from PF's own
control spacers: **block `0.5rem`, inline `1rem`** (default), **block `0.25rem`, inline `0.5rem`**
(plain/compact).

| Token | Value | Used for |
|---|---|---|
| `--sec-r-1` | `4px` (PF `border--radius--tiny`) | buttons, inputs, value wells, chips-that-are-not-pills, meter segments |
| `--sec-r-2` | `6px` (PF `border--radius--small`) | panels, the table container, the pane, the modal |
| `--sec-r-pill` | `999px` (PF `border--radius--pill`) | status chips and badges |

| Token | Light | Dark | Used for |
|---|---|---|---|
| `--sec-e-1` | `0 1px 4px 0 rgba(41,41,41,.15)` | `0 1px 4px 0 rgba(0,0,0,.5)` | the agent banner (sticky, must read as above the page); the un-docked pane |
| `--sec-e-2` | `0 10px 20px 0 rgba(41,41,41,.15)` | `0 10px 20px 0 rgba(0,0,0,.5)` | the modal, and nothing else |

**Elevation on this page is carried by surface colour, not by shadow.** `--sec-canvas` →
`--sec-surface` → `--sec-raised` is the ladder. A shadow is used only for the two things that
genuinely float above the page. Everything else gets a border.

### 2.5 The two deliberate deviations from PatternFly, with numbers

**1. The control edge.** PF's `--pf-t--global--border--color--default` is `#c7c7c7` on `#ffffff` =
**1.70:1**. WCAG 1.4.11 requires **3:1** for the visual information needed to identify a user
interface component. That border is the only thing that delimits a button, a text input, a select
and a table cell, so under PF's own value the boundary of every non-primary control on the page is
below the required contrast — and today's `--sec-border` `#d2d2d2` is worse still, at **1.51:1**
light / **1.60:1** dark. Matching PatternFly does not fix this; PatternFly fails it too.

The token is **split**:

- `--sec-line` keeps PF's value and is used only where **no control boundary is at stake**: the rule
  between two table rows, the rule under a section heading, the track of an unfilled meter. WCAG
  1.4.11 does not apply to a decorative hairline, and a table's rows are identified by their text,
  their hover state and their selection marker — not by the line between them.
- `--sec-edge` is a deliberate darker grey used on every **interactive** boundary. Computed:
  `#87898c` is **3.51:1** on `--sec-surface` and **3.13:1** on `--sec-canvas`/`--sec-inset`; dark
  `#a3a3a3` is **5.77 / 7.24**. It will look slightly heavier than stock Cockpit. That is the trade,
  and it is the right way round: a control whose edge you cannot see is a control you cannot find.

**2. The warning colour in light.** PF's `--pf-t--global--text--color--status--warning--default` is
`#dca614`, which is **2.3:1 on white** — it is a colour PF only ever paints on a tinted chip, and
using it as text would be unreadable. We keep a darkened amber `#7a5300`: **6.85:1** on
`--sec-surface`, **6.20:1** on `--sec-warn-bg`. In dark, PF's `#ffcc17` is fine (**9.63:1**) and is
used unchanged.

Everything else takes PF's value verbatim.

### 2.6 Computed contrast — the whole table

WCAG 2.x relative luminance, computed over the proposed values (`scratchpad/contrast.js`, same
formula the live probe used on the current palette). **AA text = 4.5:1. Non-text = 3:1.**

| Pair | Light | Dark | Requirement |
|---|---|---|---|
| body text on canvas | 16.31 | 18.26 | 4.5 ✓ |
| body text on surface | 18.26 | 14.55 | 4.5 ✓ |
| body text on raised (modal) | 18.26 | 11.73 | 4.5 ✓ |
| body text on inset (value well) | 16.31 | 16.48 | 4.5 ✓ |
| body text on hover row | 15.04 | 11.73 | 4.5 ✓ |
| body text on selected row | 16.00 | 13.31 | 4.5 ✓ |
| subtle text on canvas | 7.55 | 10.80 | 4.5 ✓ |
| subtle text on surface | 8.45 | 8.61 | 4.5 ✓ |
| subtle text on inset | 7.55 | 9.75 | 4.5 ✓ |
| subtle text on raised | 8.45 | 6.94 | 4.5 ✓ |
| link on canvas | 4.97 | 12.61 | 4.5 ✓ |
| link on surface | 5.57 | 10.04 | 4.5 ✓ |
| link on raised | 5.57 | 8.09 | 4.5 ✓ |
| primary button label on accent | 5.57 | 9.09 | 4.5 ✓ |
| ok text on surface | 5.73 | 6.45 | 4.5 ✓ |
| ok text on ok tint | 5.00 | 6.66 | 4.5 ✓ |
| warn text on surface | 6.85 | 9.63 | 4.5 ✓ |
| warn text on warn tint | 6.20 | 10.09 | 4.5 ✓ |
| danger text on surface | 8.21 | 6.89 | 4.5 ✓ |
| danger text on danger tint | 7.00 | 7.45 | 4.5 ✓ |
| info text on surface | 7.11 | 6.66 | 4.5 ✓ |
| info text on info tint | 5.99 | 7.36 | 4.5 ✓ |
| **control edge on surface** | **3.51** | **5.77** | **3 ✓** |
| **control edge on canvas** | **3.13** | **7.24** | **3 ✓** |
| **control edge on inset** | **3.13** | **6.53** | **3 ✓** |
| control edge on raised | 3.51 | 4.65 | 3 ✓ |
| focus ring on canvas | 4.97 | 10.07 | 3 ✓ |
| focus ring on surface | 5.57 | 8.02 | 3 ✓ |
| focus ring on raised | 5.57 | 6.46 | 3 ✓ |
| selected-row marker on surface | 5.57 | 8.02 | 3 ✓ |
| selected-row marker on sel tint | 4.88 | 7.34 | 3 ✓ |
| ok edge on ok tint | 5.00 | 6.66 | 3 ✓ |
| warn edge on warn tint | 4.48 | 6.90 | 3 ✓ |
| danger edge on danger tint | 7.00 | 4.53 | 3 ✓ |
| *hairline rule on surface (decorative)* | *1.69* | *1.52* | *n/a* |
| *hairline rule on canvas (decorative)* | *1.51* | *1.90* | *n/a* |
| *surface against canvas (elevation)* | *1.12* | *1.26* | *n/a* |

**Failures: 0.** Compare with today, where the sole failure was systemic: `--sec-border` against
`--sec-bg` at **1.51 / 1.60**, i.e. every control boundary on the page.

The tightest passing text pairs today (`--sec-sub` on `--sec-code-bg` at exactly **4.50**, `--sec-ok`
on `--sec-ok-bg` at 4.58) all move comfortably clear: the equivalents above are 7.55 and 5.00.

**Do not "simplify" a pair by reusing a colour across surfaces.** Every value in §2.2 is checked
against every surface it actually lands on, and the check is reproducible: keep
`scratchpad/contrast.js` (or an equivalent) alongside the palette and re-run it after any change.
§14 makes that a gate.

### 2.7 Typeface

Today: `font-family: "RedHatText", "Open Sans", Helvetica, Arial, sans-serif` and **zero**
`@font-face` rules. Measured — a fixed string at 64px renders at 963.53px in `RedHatText`, in
`"Open Sans"` and in `__no_such_font__` alike, and at 1028.06px in the declared stack, matching
`Arial`. `fc-list | grep -ci "red hat"` on this host is **0**. So the first two families are dead,
the page renders in the system sans, and it does so while Cockpit's own woff2 files sit unused at
`/usr/share/cockpit/static/fonts/`.

**Adopt the exact faces the shell already uses.** Measured from `shell.css`, verbatim:

```css
@font-face { font-family: "Red Hat Text"; font-style: normal; font-weight: 400 500;
             src: url(../../static/fonts/RedHatText/RedHatTextVF.woff2) format("woff2-variations");
             font-display: fallback; }
@font-face { font-family: "Red Hat Text"; font-style: italic; font-weight: 400 500;
             src: url(../../static/fonts/RedHatText/RedHatTextVF-Italic.woff2) format("woff2-variations");
             font-display: fallback; }
@font-face { font-family: "Red Hat Mono"; font-style: normal; font-weight: 400;
             src: url(../../static/fonts/RedHatMono/RedHatMonoVF.woff2) format("woff2-variations");
             font-display: fallback; }
```

```css
--sec-font:      "Red Hat Text", "RedHatText", Helvetica, Arial, sans-serif;
--sec-font-mono: "Red Hat Mono", "RedHatMono", ui-monospace, "Courier New", Courier, monospace;
```

Why this shape:

- **The URL resolves against the stylesheet, not the page.** `../../static/fonts/…` from
  `/cockpit/@localhost/secrets/secrets.css` → `/cockpit/static/fonts/…`. Verified live (P12) — 200
  on every file, and `new URL()` inside the frame resolved it to exactly that path. `font-src 'self'
  data:` permits it and the measured `securitypolicyviolation` count was **0**.
- **The variable faces cost almost nothing.** The shell already fetched `RedHatTextVF.woff2`
  (38,460 B) before our frame paints, so the text face is a cache hit. `RedHatMonoVF.woff2` is
  29,144 B and is genuinely new — spent only when a monospace glyph is painted, which on this page
  means a revealed secret, a path or a code span. That is the one place where glyph disambiguation
  is a *functional* benefit rather than a stylistic one, so it earns its 29 KB. Do **not** use the
  static per-weight files (`RedHatText-Regular.woff2` &c.): they load fine, but the shell does not
  fetch them, so they would be ~78 KB of new download for the same rendering.
- **`font-display: fallback`** is Cockpit's own choice and the right one: text paints immediately in
  the system sans and swaps if the face arrives in time. A password manager must never show a blank
  line while a font loads.
- **Weight 400–500 only.** See §2.3.

Cockpit additionally ships a `unicode-range: U+0030` data-URI override that replaces the digit zero
in the legacy `RedHatText` family. We do not copy it: our secret values are in Red Hat Mono, which
already disambiguates `0`/`O` and `1`/`l`/`I`, and copying a 2 KB base64 glyph out of another
package's stylesheet is a coupling with no benefit.

---

## 3 · Following the shell's theme

### 3.1 The problem, restated from the measurements

Cockpit does not push its theme into a plugin iframe. There is no attribute, no class, no
`postMessage`, no `cockpit.js` API — `base1/cockpit.js` contains the string "theme" zero times.
The shell writes `localStorage["shell:style"]`, dispatches a `cockpit-style` CustomEvent **on its own
window only** (measured: it never reaches the frame), resolves `auto` against
`prefers-color-scheme`, and toggles `pf-v6-theme-dark` on **its own** `<html>`.

Our page keys off `prefers-color-scheme` alone, so it is right in three of five states and wrong in
the two that a *deliberate* choice produces:

- Shell **Dark** + OS light → black shell, pure-white 1160px plugin panel
  (`artifacts/dark-03-shell-DARK-plugin-LIGHT-mismatch.png`).
- Shell **Light** + OS dark → white shell, dark plugin.

The palette itself is fine — `artifacts/dark-02-whole-window-osdark.png` shows it sitting
reasonably beside Cockpit's dark chrome. **Only the trigger is wrong.**

### 3.2 The mechanism: mirror the parent's resolved class

The siblings that get this right (`wireguard.js`, `headscale.js`) read
`localStorage["shell:style"]` and re-derive `auto` themselves. **We cannot and should not.**
`validate.sh:96` bans the bare identifier:

```
ban '\b(localStorage|sessionStorage|indexedDB|document\.cookie)\b' *.js \
    -- "I11 no browser storage of secrets"
```

Reading is harmless, but the ban is a *lexical* ban on the identifier, and that is the point of it:
it is checkable without reading the code. Adding an exception would make an auditor read the code to
trust the claim. Obfuscating the identifier to slip past it would be worse. **Neither is acceptable.**

So we read the answer the shell already computed, out of the DOM:

```js
/* theme.js — the whole file. No storage API, no network, no framework. */
(function () {
    "use strict";
    var ROOT = document.documentElement;
    /* Version-agnostic: PF5 used pf-theme-dark, PF6 uses pf-v6-theme-dark, PF7 will
       use something else. Match the family, not one release. */
    var DARK_RE = /(^|\s)pf-(v\d+-)?theme-dark(\s|$)/;

    function shellRoot() {
        /* Same-origin, measured: the plugin frame is a direct child of the shell
           (depth 1, parent === top). A standalone load has no parent and throws
           nothing — window.parent === window and the class is empty. */
        try {
            if (window.parent && window.parent !== window)
                return window.parent.document.documentElement;
        } catch (e) { /* cross-origin or blocked: fall through */ }
        return null;
    }

    function apply() {
        var host = shellRoot(), dark;
        if (host) dark = DARK_RE.test(host.className);
        else dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        ROOT.classList.toggle("sec-dark", !!dark);
        ROOT.classList.toggle("sec-light", !dark);
        /* Tells the stylesheet that JS has resolved the real preference, so the
           prefers-color-scheme fallback must stop applying. headscale.js's idea. */
        ROOT.classList.add("sec-theme-managed");
    }

    apply();

    var host = shellRoot();
    if (host) {
        new MutationObserver(apply).observe(host,
            { attributes: true, attributeFilter: ["class"] });
    } else {
        var mq = window.matchMedia("(prefers-color-scheme: dark)");
        if (mq.addEventListener) mq.addEventListener("change", apply);
        else if (mq.addListener) mq.addListener(apply);       /* older engines */
    }
}());
```

Measured (P11, §0.1): the parent is readable, its class mirrors the shell's own resolved theme in
every state including both defect states, and the `MutationObserver` fires on every transition.
Zero CSP violations. Standalone, the fallback branch is taken and is detectable.

**Why this is better than the sibling recipe, not merely legal:**

| | `localStorage["shell:style"]` | parent `<html>` class |
|---|---|---|
| Trips `validate.sh` I11 ban | **yes** | no |
| Touches any storage area | reads one | none |
| Has to re-derive `auto` | yes — duplicates the shell's logic | **no — reads the answer** |
| Can disagree with the shell | yes, if the shell's rule changes | **no, by construction** |
| Survives `localStorage.clear()` | needs an `ev.key === null` special case | irrelevant |
| Survives a browser with site data blocked | `getItem` **throws** | unaffected |
| Change signal | `storage` event | `MutationObserver` |

### 3.3 Loading it, and first paint

`theme.js` is loaded **first in `<head>`, before the stylesheet, and not deferred**:

```html
<head>
    <meta charset="utf-8">
    <title>Secrets</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <script src="theme.js"></script>          <!-- resolves the theme before any CSS is fetched -->
    <link rel="stylesheet" href="secrets.css">
    <script src="../base1/cockpit.js"></script>
    <script src="secrets.js" defer></script>
</head>
```

`document.documentElement` exists during head parsing, so the class lands before the stylesheet is
even requested and there is **no flash by construction** — which is stronger than headscale's
"script in head, DOM work on DOMContentLoaded". First-paint flash was listed as unmeasured in the
research; this ordering removes the question rather than answering it. It is 40 lines and it must
not be folded into `secrets.js`, which is 422 KB and correctly deferred.

**`install.sh` must install `theme.js`** — a new file in the package. Flagged because it is the one
non-obvious step that will silently produce a page with no theme at all.

CSS shape — the fallback stops applying the moment JS has spoken:

```css
:root { /* the complete LIGHT palette, on bare :root */ }

/* Fallback for the instant before theme.js runs, and for a page opened with JS
   disabled. Disarmed as soon as theme.js resolves the real preference. */
@media (prefers-color-scheme: dark) {
    :root:not(.sec-theme-managed) { /* the dark palette */ }
}
/* The resolved answer. Same declarations. */
:root.sec-dark { /* the dark palette */ }
```

`body` gets an explicit `background: var(--sec-canvas)`. A transparent body would borrow whatever is
behind the iframe.

### 3.4 Limits, and the test that has to exist

- **This is the one place the page reaches outside itself.** It is a read of a same-origin document
  that Cockpit itself put us inside, it writes nothing, and it observes one attribute. Say so in a
  comment at the top of `theme.js`, because a reviewer who sees `window.parent` in a security tool
  should find the justification immediately.
- **If PatternFly ever inverts the convention** — a `…-theme-light` class on a dark default — this
  reads light. The regex covers a version bump, not an inversion. The mitigation is a test, not
  more code.
- **Firefox and WebKit are unmeasured.** The research measured Chromium only. `window.parent`
  same-origin access and `MutationObserver` are universal, so the risk is low, but say it.

Required test (`tests/browser/live-ui.spec.js`), and it must assert both directions:

1. With the shell set to **Dark** and `prefers-color-scheme: light`, assert the frame's `<html>`
   carries `sec-dark` and that `getPropertyValue("--sec-canvas")` resolves to the dark value.
2. With the shell set to **Light** and `prefers-color-scheme: dark`, assert `sec-light` and the
   light value.
3. Assert the shell's own `<html>` matches `/pf-(v\d+-)?theme-dark/` in state 1 — this is what fails
   loudly, and early, if Cockpit renames the class.
4. Assert `securitypolicyviolation` count is 0 across the run.
5. **Read properties by name with `getPropertyValue`, never by iterating `getComputedStyle`.**
   Chromium enumerates custom properties; Firefox historically does not, and an enumerating test
   would pass here and fail there for no real reason.

This also closes a gap the research named: the `cockpit.permission` `changed` listener is currently
reasoned code, not measured code, because `tests/browser/harness.js` stubs `addEventListener` as a
no-op. §4.4 makes it measured.

---

## 4 · R1 — visibility follows elevation

### 4.1 The rule

- **User-class safes: always listed.**
- **Administrator-class safes: listed only while `cockpit.permission({admin:true}).allowed` is true.**
- It reacts live to the `changed` event, not only at page load.

This replaces today's behaviour, where an admin safe is listed with a disabled control and a reason.

### 4.2 Say plainly that this is cosmetic

The pane, the note in §4.3, and a comment in the code all carry the same sentence, in the page's own
voice:

> Hiding them is presentation only. The helper re-derives who is calling from the kernel and
> re-checks the access class inside every verb; that is what refuses a safe you may not open, and it
> refuses it whether or not this page drew a row for it.

This is not decoration. A page that hides rows and lets an operator infer that hiding is the control
is lying about where the security boundary is, and the footer already tells the truth ("What is
greyed out here is decoration"). That sentence stays and this one joins it.

### 4.3 The trap: admin is the DEFAULT class

A typical install is mostly admin safes (I1). An unelevated administrator would open this page, see
nothing, and conclude the tool is broken. So **whenever R1 hides anything, the page says so** — and
there are three distinct states that must be unmistakably different from one another:

**State A — some safes visible, some hidden.** One quiet line, in `--sec-fs-body` `--sec-sub`, in the
table toolbar row where a caption goes. No border, no icon, no button, no colour beyond subtle text:

> 3 administrator safes are hidden. Turn on Administrative access in the Cockpit header to see them.

**Count only. Never an id, a label, a path or a format.** Singular/plural handled ("1 administrator
safe is hidden"). It is not an alert and must not be styled as one: it is a true, unalarming fact
about a normal configuration, and a warning-coloured box that appears on every load of an
unelevated session is how a page teaches people to ignore its warnings.

**State B — nothing visible, but admin safes exist.** A full `.sec-state` panel (§8), because the
region is otherwise empty and an empty region needs an explanation, not a footnote:

> **Nothing is visible while access is limited**
> 3 administrator safes are hidden. Turn on Administrative access with the “Limited access” control
> in the Cockpit header.
> Hiding them is presentation only — the helper re-checks the access class on every operation, from
> the kernel's idea of who is calling.

**No action button.** Measured on this host: a channel opened with `superuser: "require"` is refused
immediately with `access-denied` and **no dialog is drawn**; Cockpit's escalation dialog belongs to
the shell and no package page can raise it. A button that cannot work is worse than no button.

**State C — the registry is genuinely empty.** A different `.sec-state` entirely, with a different
glyph, a different heading and, crucially, **buttons**:

> **No safes are registered**
> Make one, or register a safe file you already have.
> [ Create a safe… ] [ Import a safe file… ]
> Safes are declared by the registry in `/etc/cockpit-secrets/safes.d/`; `secrets-admin health`
> reports why an entry was dropped.

B and C are told apart by three carriers at once: **different heading text, different glyph
(key-outline vs safe-outline), and the presence or absence of action buttons.** An operator must
never have to read carefully to tell "you cannot see them" from "there are none".

The existing empty state (`renderSafes()`, the `!SAFES.length` branch) becomes C verbatim, restyled.
B and the State-A line are new.

### 4.4 Reacting live, and what happens to a safe that vanishes

`PERM.addEventListener("changed")` already exists and already drops privilege-stale caches. Extend it:

**Access granted (limited → administrative).** Admin rows appear. Sort order re-applies, so they
appear at the top. The State-A/B note disappears. Focus does not move — the operator's focus is
wherever they left it and moving it because a background condition improved is hostile. `#sec-live`
announces: "Administrative access is on. 3 administrator safes are now listed."

**Access revoked (administrative → limited), no admin safe selected.** Admin rows disappear. The
State-A/B note appears. Focus does not move unless it was inside a removed row (see below).
`#sec-live` announces the count.

**Access revoked while an admin safe is selected — the case the brief asks to be specified.**
In this exact order:

1. **If a session is open on that safe, lock it.** Call the existing lock path with the reason
   `"administrative access was turned off"`. This is not optional and it is not merely tidy: the
   helper will refuse the next verb anyway, and a page holding a live handle it can no longer use is
   a page showing stale, decrypted-looking content.
2. **`wipeAllValues()`** — every revealed value in the DOM is cleared, every reveal countdown
   cancelled, every wiper run. This already exists; it must be reached from here.
3. **Clear the clipboard**, with the reason, through the existing `clipboardClear()`.
4. **The pane stays open and switches to its "nothing selected" content.** It is not closed.
   Collapsing a pane out from under a keyboard user moves focus somewhere they did not ask for; and
   the pane's empty state is where the explanation now needs to be.
5. **The pane toggle keeps its state.** Whatever `aria-expanded` was, it stays. The pane's *content*
   changed; its *disposition* did not, and the operator did not touch the toggle.
6. **Focus:** if focus was inside the pane or inside the removed row, move it to `#sec-main` (already
   `tabindex="-1"`). Otherwise leave it. Never move focus to a node that is about to be removed, and
   never let focus fall to `<body>` — that loses the operator's place entirely.
7. **An assertive alert** in `#sec-alerts`, because this interrupts what the operator was doing:
   > Administrative access was turned off. **safe-name** was locked and everything shown from it was
   > cleared. Administrator safes are hidden until access is on again.
   The safe's **label** is named here, deliberately — the operator had it selected a moment ago, so
   this discloses nothing they were not already looking at, and an anonymous "a safe was locked" is
   useless.
8. `#sec-live` gets the count sentence as well, politely.

**These paths are currently untested** — `tests/browser/harness.js` stubs `addEventListener` as a
no-op, so the `changed` listener is reasoned code. The live suite can drive the real control:
`live-harness.js` already exposes `adminAccessState(page)`. Required new live tests: (a) revoke with
an admin safe selected-and-locked → row gone, pane empty-stated, note shows the right count, focus is
on `#sec-main`, no id or path anywhere in `document.body.innerText`; (b) grant → rows return, count
note gone.

---

## 5 · R2 — the safes table

### 5.1 Structure

A real `<table>` in a `.sec-scroll` container (`overflow-x: auto`), with a real `<thead>`, real
`<th scope="col">`, and a `<caption>` carrying the count and the State-A note.

```html
<div class="sec-tablewrap">
  <div class="sec-toolbar">…count / hidden-note… <details class="sec-columns">Columns</details></div>
  <div class="sec-scroll">
    <table class="sec sec-safes-table">
      <thead><tr>
        <th scope="col" aria-sort="none"><button type="button">Safe <span aria-hidden="true">▲</span></button></th>
        …
      </tr></thead>
      <tbody>
        <tr class="sec-safe">
          <td><button type="button" class="sec-rowdoor" aria-current="true">
                <span class="sec-safe-label">Lab domain controller</span>
                <span class="sec-safe-id">lab-dc</span>
              </button></td>
          …
        </tr>
      </tbody>
    </table>
  </div>
</div>
```

**Keep the class names `.sec-safe` and `.sec-safe-id`** on the row and the id text. They are not
decoration: the browser suites select on them 30 and 25 times. §12 covers the migration.

### 5.2 Columns

**Default, in this fixed order:**

| # | Column | Content | Sort key | Why it is here |
|---|---|---|---|---|
| 1 | **Safe** | label in `--sec-fw-med`, id beneath in `--sec-fs-sm` `--sec-sub` monospace | label, then id | The row's identity and its keyboard door. Two lines, because the label is what an operator recognises and the id is what every verb and every error message uses. |
| 2 | **Class** | chip: “Administrator” / “Yours” | admin first | The single most consequential fact about a safe. It decides what escalation an operation needs, whose file it is, and — under R1 — whether the row exists at all. |
| 3 | **Format** | chip: “KDBX 4”, “Password Safe v3”; from the probe when known, the registry row when not | format, then version | It decides which warnings apply (a KDBX3 file is not authenticated, I20) and whether a round trip can carry every field. |
| 4 | **State** | up to two chips + “+N” (§5.4) | severity rank | Everything that would make an operator stop: read-only, not writable, keyed, key file, agent enabled, unreachable, warnings present. |

Four columns. That is the whole of what an operator needs in order to *choose which safe to open*.

**Deliberately not default columns:** anything requiring the safe to be open (entry counts, last
entry modified) — never; and the five optional columns below.

**Optional, in this fixed order when enabled:**

| Column | Content | Default | Why optional |
|---|---|---|---|
| **Path** | the registry `path`, wrapping | **off** | §5.6 |
| **Registry** | “System” / “Yours” | off | Who says this file is a safe — root-owned policy vs an entry the caller wrote. Interesting during triage, noise otherwise. |
| **KDF** | “Argon2id · 19 iterations” | off | From the probe; empty until probed. A tuning and forensics detail. |
| **Modified** | timestamp, tabular | off | Offered **only if a visible row carries the field** (see below). |
| **Id** | the id alone | off | Already under the label; a separate column exists so a large registry can be sorted and scanned by id alone. |

**General rule that makes the chooser honest:** a column is offered **only when at least one
currently visible row could fill it.** A helper that does not publish `modified` never shows a dead
checkbox, and nothing has to be special-cased for it. This is why `Modified` is in the list at all
despite not being in the contract's list-row shape.

**Column order never changes.** It is fixed by this document, not by the order the operator ticked
the boxes. A table whose columns move under you is a table you have to re-read every time.

### 5.3 Sorting

- Each sortable `<th>` contains a real `<button>`; the `<th>` carries `aria-sort="ascending" |
  "descending" | "none"`.
- The direction glyph is `▲`/`▼` with `aria-hidden="true"` — `aria-sort` is the accessible carrier,
  the glyph is the visual one, and neither is colour.
- **Default sort: Class (administrator first), then Safe label.** Admin first, because admin is the
  default access class and the list should read in the order the registry defaults do.
- Clicking any header sorts purely by that column, ascending first, toggling on re-click. Clicking
  **Class** toggles administrators-first / yours-first.
- A “Reset sort” is not provided; re-clicking Class restores the default grouping and that is
  enough.
- Sorting is client-side over the rows in hand, exactly as `renderEntries()` already does.

### 5.4 The State cell

Every state an operator must not miss, as chips. **At most two chips are drawn**, in severity order,
then `+N` as a `.sec-btn.link` that selects the row and opens the pane (where all of them are listed
in full). Rationale: a row with six chips is a row nobody reads.

| Severity | Chip | Colour | Condition |
|---|---|---|---|
| 1 | **Unreachable** | danger | `safeReachable()` is false — the helper's own refusal for a user-class safe |
| 2 | **Warnings (N)** | warn | the probe returned `warnings[]` |
| 3 | **Not writable** | warn | `probe.writable === false` |
| 4 | **Read-only** | warn | `safe.mode === "ro"` |
| 5 | **Agent enabled** | warn | `safe.agent_enabled` |
| 6 | **Key file** | neutral | `needs_keyfile` |
| 7 | **Keyed** | neutral | `password_required === false` |
| — | *(empty cell)* | — | nothing to say. **An empty cell, not a “Normal” chip.** |

Chips are `--sec-fs-sm`, `--sec-r-pill`, tinted background, tinted edge (all three measured ≥ 4.5:1
text and ≥ 3:1 edge, §2.6). **Every chip's meaning is its word.** Colour is a second carrier and never
the only one.

**Important, and it must not be lost in the move:** an **administrator-class** safe is never marked
unreachable. Measured and documented at length in `secrets.js` — `list` is always spawned
unescalated, so it returns `usable:false` for every admin entry, for every caller, in every session.
That verdict carries no information and reading it as a refusal is what disabled the default access
class permanently. `safeReachable()` already encodes this. The State cell must call it, not
re-derive it.

### 5.5 Rows: activation, selection, density

**Activation.**
- The first cell contains one `<button class="sec-rowdoor">`. It is the accessible control; the
  whole `<tr>` also carries a click handler as a convenience (`cursor: pointer`).
- Clicking either selects the safe and shows it in the pane. **Nothing else in the row is
  clickable.** No action buttons live in rows — see §7.2.
- Keyboard: the row buttons are ordinary tab stops in DOM order (a registry is a handful of rows;
  the entries table is capped by its page size). Additionally, when focus is on a row button:
  **↓ / ↑** move focus to the next / previous row button, **Home / End** to the first / last, and
  **Enter / Space** activate natively. Arrow handling calls `.focus()` on a sibling; it does not
  change the tab count and it does not need a roving `tabindex`.

**Selection — three carriers, so it survives greyscale and colour-blindness:**
1. `background: var(--sec-sel)` on the row's cells;
2. `box-shadow: inset 3px 0 0 var(--sec-accent)` on the first cell — a 3px bar, measured **5.57:1**
   light and **8.02:1** dark against the surface, so it satisfies WCAG 1.4.11 on its own;
3. `aria-current="true"` on the row button, and the label at `--sec-fw-med`.

The selection **persists while the pane is open** and is cleared only by selecting another row, by
the safe disappearing (§4.4), or by locking.

**Density.** Cell padding `var(--sec-s-2) var(--sec-s-3)` (8px / 16px), `--sec-fs-body`,
`--sec-lh-body` → ~37px rows. Row separator: `border-block-end: 1px solid var(--sec-line)`. Header
cells: `--sec-fs-sm`, `--sec-fw-med`, `--sec-sub`, `white-space: nowrap`, a 1px `--sec-line` rule
beneath. Hover: `background: var(--sec-hover)` on the row.

**Truncation: none, anywhere.** Every long value wraps (`overflow-wrap: anywhere`); the table
scrolls inside `.sec-scroll` when it must. A truncated safe id or path is a value an operator can
mis-identify or fail to copy, and mis-identification in this product means opening the wrong safe.
Measured today at a 360px frame: the entries table is 448px inside a 328px cell, `.sec-scroll`
absorbs it, and `document.documentElement.scrollWidth` stays 360 — correct behaviour that this design
extends to the safes table, which today is a card grid and has no such wrapper.

### 5.6 The Path column and the chooser (R5)

**Where the chooser lives.** A `<details class="sec-columns">` in the table's toolbar row, right-
aligned. `<summary>` reads **“Columns”**, and **“Columns · 1 extra”** when any optional column is on,
so the state is visible without opening it.

Why a disclosure rather than a popup menu: it needs no focus trap, no outside-click handler, no
positioning maths and no `aria-expanded` bookkeeping (the `<details>` element carries all of that
natively); it degrades correctly with CSS off; and at 200% zoom it simply reflows instead of
overflowing a viewport. It pushes the table down when open. That is honest and costs nothing.

**Contents:**

```html
<details class="sec-columns">
  <summary>Columns · 1 extra</summary>
  <fieldset class="sec-radios">
    <legend>Optional columns</legend>
    <div class="sec-checklist">
      <label class="sec-check"><input type="checkbox" name="col-path"> Path
        <span class="hint">Where each safe's file lives. Off by default.</span></label>
      <label class="sec-check"><input type="checkbox" name="col-registry"> Registry</label>
      <label class="sec-check"><input type="checkbox" name="col-kdf"> KDF</label>
      <label class="sec-check"><input type="checkbox" name="col-modified"> Modified</label>
      <label class="sec-check"><input type="checkbox" name="col-id"> Id</label>
    </div>
    <button type="button" class="sec-btn link">Reset to defaults</button>
  </fieldset>
</details>
```

- Two columns at ≥ 40rem, one below. “Reset to defaults” is rendered only when the selection differs
  from the default.
- Toggling a box **re-renders immediately** — no Apply button. Announce into `#sec-live`:
  “Path column shown. Five columns.”
- **Keyboard:** Tab to the summary; Enter/Space opens; Tab through the checkboxes; **Escape closes
  the disclosure and returns focus to the summary** (this needs one `keydown` handler — `<details>`
  does not do it natively).

**Why Path is off by default — three reasons, all of them, so nobody later “fixes” it:**

1. **It discloses.** A path names a home directory and therefore an account, and it names the
   host's filesystem layout. This page gets screenshotted — every artefact in
   `tests/browser/artifacts/` is proof — and the default view should not carry that.
2. **It does not scan.** It is by a wide margin the longest value in the row and the only one that
   must wrap. One Path column turns a four-line table into a twelve-line one.
3. **It is the wrong question at this moment.** Choosing which safe to open is done by label, class
   and format. “Which file is this, exactly” is a question that arises when something is *wrong* —
   which is exactly when the operator opens the details pane, where it always is.

And the counterweight, which is why it is not simply omitted: **a safe you cannot locate on disk is
a safe you cannot back up, cannot repair and cannot prove is the one you meant.** It is always in
the pane, in full.

---

## 6 · R3 / R4 — the details pane and its toggle

### 6.1 What the pane contains, per state

The pane is a content stack: exactly one of four contents, with a header naming which.

```html
<aside id="sec-pane" class="sec-pane" role="complementary" aria-labelledby="sec-pane-h">
  <div class="sec-pane-head">
    <button type="button" class="sec-btn link" id="sec-pane-back" hidden>← Safe details</button>
    <h2 id="sec-pane-h" tabindex="-1">…</h2>
  </div>
  <div id="sec-pane-body">…</div>
</aside>
```

`.sec-pane` is `background: var(--sec-surface)`, `border: 1px solid var(--sec-edge)`,
`border-radius: var(--sec-r-2)`, `padding: var(--sec-s-3)`. The edge uses `--sec-edge` and not
`--sec-line` because the pane is a region a keyboard user must be able to see the extent of.

---

**(a) Nothing selected** — the default on load.

Heading: **“No safe selected”**. One line: “Choose a safe from the table to see its registry entry,
its file header, and what it will take to open it.” Then, because these facts otherwise have no
readable home, a small `<dl>`:

- **Helper** — version and verb count (the same facts `#sec-sub` compresses into the topbar)
- **Reveal window** — “15 s”, from `uiNum("reveal_seconds", 15)`
- **Registry** — the directories in play, from `registryDirs()`

An empty pane that teaches beats an empty pane that apologises. This is styled as a `.sec-state`
**without** the glyph — it has content, so it is not really an empty state, but it belongs to the
same family.

---

**(b) A safe is selected and locked** — the normal state. Sections in this order:

1. **Identity.** Label as the pane heading (`--sec-fs-h3`, wraps). Beneath: the id in
   `--sec-font-mono` `--sec-sub`, then the Class and Format chips.
2. **Path — always, in full, wrapping, selectable.** In the `.sec-path` well style
   (`--sec-inset`, `--sec-font-mono`, `--sec-fs-body`, `overflow-wrap: anywhere`,
   `white-space: pre-wrap`). Never truncated, never `~`-abbreviated. Beside it a **“Copy path”**
   tiny button.
   Followed by one sentence naming what the location *means*, chosen from exactly three cases —
   never guessed:
   - **user class, under the caller's home:** “In your own home directory. The helper opens it
     running as you, with no escalation, and the file must be owned by you.”
   - **system registry, under `/etc/cockpit-secrets/safes/`:** “Declared by the system registry and
     owned by root. Every operation on it is spawned with Cockpit's administrative access, and the
     helper refuses the verb unless it is running as root.”
   - **anything else:** the path alone, with no editorial sentence.
   **The path is not a secret, and copying it must not arm the clipboard countdown** — see §7.4.
3. **Header facts**, from the probe, as a `<dl class="sec-kv">`: format + version, KDF + iterations,
   writable, needs key file, needs passphrase. When unprobed: one `--sec-sub` line “The file header
   has not been read yet.” plus the **“Check this safe”** button, which moves here off the row.
   Keep its existing two-state title text verbatim — it is carefully worded and it is correct.
4. **Warnings**, verbatim from the helper, as `.sec-alert.warn` blocks. The KDBX3
   “not authenticated” banner (I20) lands here.
5. **Actions**, on the ladder — §7.2.

---

**(c) A safe is selected and unlocked** — the browse view. **The pane becomes the entry detail**, and
the safe's own identity moves to a compact strip above the entries table (label, chips, entry/group
counts — today's `#sec-browse-meta`).

Two docked panes is not a design, it is a failure to choose. With a safe open, the thing an operator
looks at over and over is the entry, and it is the thing that most needs the width. The safe's
registry detail stays one click away: `#sec-pane-back` (“← Safe details”) swaps the pane's content
back **without** deselecting the entry, and a forward control returns.

Inside the pane, the entry detail nests exactly as §10 specifies.

The groups tree keeps its own place in `#sec-main`, to the left of the entries table:
`#sec-main { display: grid; grid-template-columns: 15rem minmax(0,1fr); }` at ≥ 78rem, `13rem` at
≥ 60rem, and **below 60rem it becomes a `<details>` disclosure above the table** — summary
“Groups · Root/Servers”, contents the same `<ul>` of buttons. Same reasoning as the column chooser:
no overlay, no trap, no positioning.

The tree's indentation is set today with `b.style.paddingLeft = (0.35 + depth * 0.75) + "rem"`.
Change it to a custom property on the button — `b.style.setProperty("--sec-depth", depth)` with
`padding-inline-start: calc(var(--sec-s-1) + var(--sec-depth, 0) * var(--sec-s-2))` — which is the
brief's preferred form and keeps the step on the spacing scale.

---

**(d) Unreachable.** Identity and path as in (b); then the helper's own `reason` sentence in a
`.sec-alert.err`; then the action group present but disabled. **The reason is visible text under the
action row as well as a `title`.** A `title` alone is invisible to touch, to most screen readers in
browse mode, and to anyone who does not hover.

### 6.2 Unlock stays a modal — decided, with reasons

The unlock does **not** happen in the pane.

1. It is the moment that must have the operator's whole attention. A pane competing with a table
   behind it is the opposite of that.
2. It needs a focus trap and Escape-to-cancel. A docked pane that trapped focus would be a pane you
   cannot leave, and Escape inside the pane already means “collapse” (§6.4).
3. Its content is dialog-sized: a class-dependent intro, a key-file notice, a wall of probe
   warnings, an optional YubiKey challenge step, the passphrase control, and the actions. In a 384px
   column that is a scroll box.
4. The existing modal is built, keyboard-correct and covered by 309 test assertions on `.sec-modal`.
   Moving it into the pane trades a working thing for a novelty.

The pane's **Unlock…** button opens the existing modal. On success the view switches to browse and
the pane switches to content (c).

### 6.3 The toggle (R4)

```html
<button type="button" id="sec-pane-toggle" class="sec-btn sec-iconbtn"
        aria-expanded="true" aria-controls="sec-pane">
  <svg …/><span class="sec-iconbtn-text">Details</span>
</button>
```

- **A real `<button>`**, with `aria-expanded` and `aria-controls`. Accessible name: **“Details
  pane”** (an `aria-label`, always present). The name names the *thing*; the *state* is
  `aria-expanded`, which is why it is not “Show details” / “Hide details”.
- The visible text “Details” is rendered at ≥ 48rem and hidden below (`.sec-iconbtn-text` becomes
  `.sec-visually-hidden` under a media query — hidden visually, never removed from the accessibility
  tree).
- **Position: last in `.sec-topbar-actions`**, i.e. the rightmost control — spatially above the
  pane's own edge, which is the only position that says what it does. Order left to right:
  status chips (`#sec-dirty`, `#sec-clip`, `#sec-session`) → **Refresh** → **Lock** *(danger)* →
  **gap of `var(--sec-s-3)`** → **pane toggle**. The gap is not decoration: it is what stops a
  mis-aimed click on a frequently-pressed toggle from landing on the one control that discards an
  open session.

**The icon — the one place this design overrides a stated requirement.** R4 says “a hamburger”.
The three glyphs `☰` universally mean *navigation menu*; this control docks and undocks a side
panel, and using the menu glyph for it would be the single most confusing choice on the page. So:

> **An inline `<svg>` panel-right glyph** — a rounded rectangle, 16 × 16, `stroke: currentColor`,
> `stroke-width: 1.5`, with the right-hand third filled — mirrored under `dir="rtl"` via
> `transform: scaleX(-1)` on `[dir="rtl"] &`. Built in JS with `document.createElementNS`, no
> external asset, no icon font, `fill`/`stroke` inheriting `currentColor` so it themes for free.

R4's actual requirement — a real button, with `aria-expanded`, with an accessible name, that
expands and collapses the pane — is met in full. Only the glyph differs, and if the operator prefers
the hamburger it is one line: replace the `<svg>` with a text node `"☰"` and give it
`aria-hidden="true"`. **Flagged so the operator can overrule it.**

### 6.4 Focus, in every direction

| Moment | Focus goes to | Why |
|---|---|---|
| Pane **opened by the toggle** | the pane heading (`#sec-pane-h`, `tabindex="-1"`) | The operator asked for the pane; putting them in it saves tabbing past the whole table. `#sec-live`: “Details pane shown.” |
| Pane **opened by selecting a row** | **stays on the row button** | The intent was to choose a safe. Yanking focus out of the table breaks ↓/↑ scanning. `#sec-live`: “Details for *label* shown in the details pane.” |
| Pane **closed by the toggle** | back to the toggle | Standard, and the toggle is where the operator's hand is. |
| Pane closed **while focus is inside it** (Escape) | the toggle | Never let focus fall to `<body>`. |
| **Escape pressed inside the pane** | collapses the pane, focus → toggle | Safe because **the pane contains no free-text entry** — every mutation on this page goes through a modal. That is the invariant that makes Escape harmless; if it is ever broken, this rule must be revisited. Escape is swallowed by an open modal first (the modal's own handler already runs). |
| Row selected while the pane is **un-docked** (< 60rem) | the pane heading, after `scrollIntoView({ block: "start" })` | At this width the pane is off-screen; “it appeared somewhere below” is not discoverable. `behavior: "smooth"` only under `prefers-reduced-motion: no-preference`; otherwise `"auto"`. |
| Selected row **disappears** (elevation revoked) | `#sec-main` | §4.4 step 6. |
| Safe **locked** | the safes table's first row button, or `#sec-main` if the table is empty | The view changed under the operator; land them at the top of the new one. |

**A second skip link.** When the pane is open, a “Skip to details” link joins `.sec-skip` in the
skip stack. It is the standard answer to “there is a long table between me and the pane”, it costs
one element, and it is the only thing that makes the pane reachable in one keystroke from the top of
the page.

---

## 7 · The consequence ladder

### 7.1 Four rungs

| Rung | Actions | Control style | Confirmation | Aftermath |
|---|---|---|---|---|
| **0 · read** | browse, search, sort, check header, list backups, copy a path | default `.sec-btn`: `--sec-ink` on `--sec-surface`, 1px `--sec-edge` | none | none |
| **1 · momentary disclosure** | Reveal, Copy a value, TOTP | default `.sec-btn.tiny` + a key glyph; the consequence is carried by the **result**, not the control | none | the value re-hides on its deadline; the clipboard is cleared and the chip says so |
| **2 · durable disclosure** | **Export** | `.sec-btn.danger`: `--sec-danger` text **and** border on `--sec-surface`. **Not a filled red button.** | a modal whose body is a `.sec-danger-block` naming the destination directory, **plus** an explicit checkbox the operator must tick | the result reports path and size, never contents |
| **3 · irreversible** | **Delete** | `.sec-btn.danger`, last in the group, `var(--sec-s-3)` before it | modal, `.sec-danger-block`, **plus type-the-id** (already built); Confirm stays `disabled` until the id matches exactly | no undo, and the copy says so |

**Forget** is deliberately *not* on this ladder. It sits with the destructive group (it removes the
safe from the page) but is styled as a **default** button, with one line beneath it: “Removes the
registry entry only. The file and its backups stay where they are, and registering it again brings
it back.” Reversible actions must not wear the irreversible costume; if they do, the costume stops
meaning anything.

### 7.2 The rules that make it legible rather than decorative

**1. No action buttons in table rows.** Every action lives in the pane. Consequence: there is exactly
one place where a destructive control can be, exactly one place its disabled/reason logic lives, and
a row can never be a thing you accidentally *do* something to — a row is a thing you *select*. This
is also what makes the table scannable at 37px rows.

**2. A filled red button appears nowhere in this product.** The only filled button is the primary
accent, and the only primary button on a screen is the safe, expected action (Unlock; Save; and, in
a dialog, the confirm whose danger has *already* been stated). A filled red destructive button trains
the eye to find red and press it; an outlined one has to be read.
*Judgement call, and the trade:* Delete is slightly less obvious in exchange for a Delete nobody hits
by reflex. **One stated exception:** inside a rung-3 modal, once the typed id matches, the Confirm
button becomes filled `--sec-danger` with `--sec-inverse`. By then the operator has typed a safe's id
to get there; making the last control unmissable is a kindness, not a trap.

**3. Rung 2 and 3 controls are never adjacent to rung 0 or 1 controls.** In the pane the action area
reads top to bottom:

```
[ Unlock… ]                            ← primary, alone on its row
[ Backups… ]  [ Check this safe ]      ← rung 0, one row
────────────────────────────────────   ← 1px --sec-line rule
Destructive                            ← .sec-eyebrow, --sec-fs-sm --sec-fw-med --sec-sub
[ Export… ]  [ Forget… ]  [ Delete… ]  ← role="group" aria-label="Destructive actions"
Forget removes the registry entry only…
```

Both carriers: a visible rule and eyebrow for sighted users, a labelled `role="group"` for AT.

**4. Consequence is carried by the result, not only by the control.** A Reveal button looks calm
because pressing it is calm; what is *not* calm is a plaintext password sitting on screen, and that
is exactly where the weight goes — a bordered well, a countdown bar, a running numeral (§7.4).

### 7.3 The agent banner — the loudest thing on the page (I18)

An agent-held unlock is the one state where a safe is open while nobody is looking at it, so its
banner must be unmissable from every view. It already is, structurally: full width, above the view
switch, `position: sticky; top: 0`, and it collapses to nothing via `:empty` when the agent holds
nothing — which is the default, because the agent is opt-in per safe. **Keep every one of those
properties.** In particular keep `role="region"` (not `alert` — the countdown ticks once a second and
an assertive region would interrupt a screen reader on every tick) and keep the one polite
announcement when the *set* of held safes changes.

Restyled:
- `background: var(--sec-warn-bg)`, `border: 1px solid var(--sec-warn-edge)`, a **4px
  `--sec-warn-edge` left bar**, `border-radius: var(--sec-r-2)`, `box-shadow: var(--sec-e-1)` so it
  reads as sitting above the page that scrolls under it.
- A **key glyph** and the word **“Unlocked”** in the heading, so the state does not rest on amber
  alone: “**Unlocked** — a safe is held open by the agent”.
- The countdown at `--sec-fs-body` (**not** the current small size), `--sec-fw-med`,
  `font-variant-numeric: tabular-nums`. A deadline is not a footnote.
- The per-row **Lock now** stays `.sec-btn.danger`. It is rung 3 by consequence but it is also the
  only way out, so it is prominent — an exception to §7.2's separation rule, stated: the banner
  contains nothing *but* destructive-and-desirable actions, so there is nothing to separate it from.
- It spans the full width **above** `#sec-workspace`, never inside a grid column. It must never be
  pane-width.

### 7.4 Reveal, copy, and the countdowns

**The value well.** `--sec-inset` background, 1px `--sec-edge`, `--sec-r-1`, `--sec-font-mono`,
**`--sec-fs-lg` (16px — larger than body**, because a password is read character by character),
`white-space: pre-wrap`, `overflow-wrap: anywhere`, `min-block-size: 2.5rem`.

**The deadline is carried three ways**, so it survives greyscale, reduced motion and a glance:

1. **A bar** — a `0.25rem` track directly under the well, `--sec-line` background, one hue
   (`--sec-accent`) fill. The width is driven by **one custom property set on the container**:
   ```js
   well.style.setProperty("--sec-remain", pct + "%");   /* CSS: width: var(--sec-remain, 100%) */
   ```
   This replaces the three `bar.style.width = … + "%"` assignments at `secrets.js:2765`, `:2777` and
   `:7315`. It is the brief's preferred form, it keeps the number out of a string-built style, and it
   means the bar's geometry lives entirely in the stylesheet.
2. **Numerals** at the right of the well's head row: `--sec-fs-sm`, `tabular-nums`,
   `aria-hidden="true"`. The polite region carries the sentence once per state change, not once per
   second — that is already right and must not regress.
3. **The last five seconds**: the numerals go `--sec-fw-med` and `--sec-danger`, and the bar switches
   to `--sec-danger`. Colour changes *and* the numeral itself is the text carrier, so colour is never
   alone.

**`prefers-reduced-motion: reduce`** removes the *transition*, not the countdown. The bar steps once
per second — a state change, not an animation. Keep exactly the existing idiom, which gates
transitions behind `@media (prefers-reduced-motion: no-preference)` rather than switching them off
under `reduce`; that way the motion is opt-in and a browser that reports nothing gets the still
version.

> **A deadline you cannot see is worse than a deadline that jumps.** Nothing here may be removed
> under reduced motion.

**The clipboard countdown is armed for secrets only.** Today `copyValue()` arms it for everything it
is called with, including the export destination path and the YubiKey challenge — neither of which is
secret, and the challenge is *by construction* worthless to an attacker. A chip that cries wolf
teaches an operator to ignore the one that matters. Specify: `copyValue(value, { secret: true })`,
default `false`; the chip and the countdown appear only for `secret: true`; “Copy path” and “Copy the
challenge” pass `false` and get a plain, momentary “Copied” confirmation instead.
*(This is a behaviour change in `secrets.js`, not a CSS change. It is a design decision because the
chip is a design element that currently lies.)*

---

## 8 · Empty, loading, error and locked-out

One component, `.sec-state`, so the four read as a family — and five instances, each unmistakably
itself.

```css
.sec-state { display: flex; flex-direction: column; align-items: center; text-align: center;
             gap: var(--sec-s-2); max-inline-size: 34rem; margin-inline: auto;
             padding: var(--sec-s-5) var(--sec-s-3); }
.sec-state .glyph   { inline-size: 2rem; block-size: 2rem; color: var(--sec-sub); }
.sec-state h3       { margin: 0; font-size: var(--sec-fs-h3); font-weight: var(--sec-fw-med);
                      line-height: var(--sec-lh-heading); }
.sec-state p        { margin: 0; color: var(--sec-sub); }
.sec-state .actions { display: flex; flex-wrap: wrap; gap: var(--sec-s-2);
                      justify-content: center; margin-top: var(--sec-s-2); }
```

| # | State | Glyph | Heading | Body | Actions |
|---|---|---|---|---|---|
| 1 | **Loading the registry** | none | none | `--sec-sub`: “Reading the safe registry…” | none — plus a **skeleton table** of three rows in `--sec-inset` |
| 2 | **No safes registered** | safe/box outline, `--sec-sub` | “No safes are registered” | “Make one, or register a safe file you already have.” + a `--sec-fs-sm` line naming the registry directories and `secrets-admin health` | **Create a safe… · Import a safe file…** |
| 3 | **All hidden by elevation** | key outline, `--sec-sub` | “Nothing is visible while access is limited” | the §4.3-B copy, including the “presentation only” sentence | **none** — no page control can escalate (measured) |
| 4 | **The helper did not answer** | warning triangle, `--sec-danger` | “The helper did not answer” | the helper's error verbatim in a `.sec-pre`, then: “This page renders only what `secrets-admin` describes through its schema verb. Install it with `install.sh` from this package.” | **Retry** |
| 5 | **Locked out (I16)** | lock, `--sec-warn` | “Too many failed attempts” | the helper's sentence, plus its `retry_after` as a **live countdown** with the §7.4 treatment — bar and tabular numerals — because it *is* a deadline | Unlock, **disabled** until zero |

Notes that are part of the spec:

- **The skeleton never shimmers — for anyone, not only under reduced motion.** A pulsing block behind
  a security tool reads as activity that is not happening. It is a static `--sec-inset` tint at the
  table's real row height, so the layout does not jump when the rows arrive. A spinner says “wait”;
  a skeleton says “a table is coming and it will be about this big”, which is the true statement.
- **State 5 must not re-enable silently.** When the countdown reaches zero the heading changes to
  “You can try again”, the Unlock button re-enables, and `#sec-live` says so once.
- **States 2 and 3 differ in three ways at once** — heading, glyph, and the presence of buttons.
  §4.3.
- The pane's “nothing selected” content (§6.1a) uses `.sec-state` **without** a glyph. It has
  content; it is a resting state, not an empty one.

---

## 9 · The no-persistence trade — pane state and column selection

Say it once, and say it as a decision:

> `validate.sh` bans `localStorage`, `sessionStorage`, `indexedDB` and `document.cookie` as bare
> identifiers anywhere in the package's JavaScript (I11), and `tests/browser/live-ui.spec.js`
> additionally fails the run if **any** storage key changes during it — `HOST_SHELL_KEYS =
> ["cockpit:page_status"]` is the only tolerated name. Remembering the pane's position or the
> operator's column choice across reloads would need one of those APIs.
>
> **The ban is worth more than the convenience.** It is the mechanical guarantee that nothing about a
> safe can be left behind in a browser, and it is checkable by grep — a ban with one exception is a
> ban an auditor has to read the code to trust.
>
> So both settle to a good default on every load (§1.3, §5.6) and live in ordinary variables for the
> life of the page. **This is a deliberate trade, not an oversight.**
>
> If it is ever revisited, the right answer is not a storage exception: it is a helper-side
> `ui-prefs` verb, so preferences live on the host, in the registry, under the same access class and
> the same audit line as everything else this program does.

The same paragraph, compressed to two sentences, belongs in a comment beside each in-memory flag, so
the next person to read the code finds the reasoning where the question occurs to them.

---

## 10 · Entry list and entry detail

### 10.1 The entry list

Same table spec as §5 — the two tables are the same component with different columns. Columns come
from `listColumns()`, which is schema-driven; **do not hard-code a column set here.** Per-type rules:

| Field | Treatment |
|---|---|
| **Title** | the keyboard door, `--sec-fw-med`, wraps. “(untitled)” in `--sec-sub` italic when empty. |
| **Username** | `--sec-font-mono`, `--sec-fs-body`. **Judgement call:** usernames are *compared*, not read — a monospace column makes `admin1` and `admin l` distinguishable at a glance. It is not a secret and gets no well and no countdown. |
| **URL** | wraps at `overflow-wrap: anywhere`, cell capped at `max-inline-size: 22rem`. Wrapped inside its cap, never truncated, and **never a live link** — see §10.2. |
| **Tags** | neutral chips (`--sec-inset` background, `--sec-sub` text, `--sec-fs-sm`). At most three, then “+N” as a `.sec-btn.link` that selects the row. Not a tooltip: a tooltip is unreachable by touch and by keyboard. |
| **TOTP / Attachments** | a `✓` glyph plus `<span class="sec-visually-hidden">has TOTP</span>`; **an empty cell for false.** Today these are `badge("yes")`/`badge("no")`, which spends a whole chip on a boolean and fills the table with the word “no”. |
| **Modified** | `--sec-fs-sm`, `--sec-sub`, `tabular-nums`. |
| **Booleans generally** | same as TOTP: glyph + hidden word for true, empty for false. |

**An expired entry — three carriers, never colour alone:**
1. a `⚠` glyph before the title (`aria-hidden`, it is decorative — the word carries it);
2. a chip **“Expired”** in `--sec-warn` immediately after the title;
3. the expiry/modified value rendered in `--sec-warn`;
and the row button's `aria-label` reads “*title*, expired”.

**Never strikethrough.** Struck-through text is unreadable at 12–14px and it reads as *deleted*,
which an expired entry is not.

### 10.2 The entry detail, inside the pane

Order, top to bottom:

1. **Title** as the pane heading, `--sec-fs-h3`, wraps.
2. **Metadata `<dl class="sec-kv">`.** `grid-template-columns: minmax(6rem, auto) minmax(0, 1fr)`,
   `--sec-fs-body`, `dt` in `--sec-sub`, `dd` wrapping. **Below a 22rem pane width the `<dl>` becomes
   a single column** with the `dt` above its `dd` — a two-column definition list in a 20rem pane is
   two columns of hyphenated fragments.
   Keep the existing exclusions exactly: `title`, `uuid`, `_`-prefixed bookkeeping,
   `attachment_names`, and every `CUSTOM_ROW_KEYS` name. That exclusion is a defence (a row that
   carried `[{name, value}]` would otherwise print a secret with no mask and no countdown), not a
   layout choice, and it must survive the restyle.
3. **A long URL** is a wrapping `<code>`-styled line with a **Copy** control — **not an anchor.**
   *This is a security decision wearing layout clothes and it belongs in this document:* a URL inside
   a safe is attacker-controlled data (threat model A3, “a malicious or corrupted safe file”).
   Rendering it as a live link lets a safe's contents navigate the operator's browser on one
   mis-click. It is presented as text, and the operator copies it if they want it.
4. **A multi-line note.** `white-space: pre-wrap`. Clamped to the first **8 lines**, followed by a
   `<button class="sec-btn link">Show the whole note (N lines)</button>`. Not a scroll box: a
   scrollbox inside a pane inside a page is three nested scrolls and the middle one is always the
   one the wheel does not reach.
   **The rule that decides which path a note takes:** if the field is in `revealFields()` it is a
   protected value and goes through `revealWidget` with its well and its countdown, and this clamp
   does not apply. If it arrives in the entries row it is metadata and the clamp does apply. Read
   the schema; do not assume either way.
5. **Tags** — the same chips as the list, wrapping, no cap here.
6. **Fields** — one `revealWidget` per `revealFields()` entry, exactly as today. Keep the existing
   rule that a field already carried in the listing is not re-offered, except `password` and `totp`.
7. **Custom fields.** Keep the name-plus-reveal-widget structure. Two changes:
   - the `protected` / `not protected` chip moves to the **left** of the field name (it qualifies the
     name, so it reads before it) and carries a filled/hollow dot glyph *plus* the word;
   - the sentence “stored in the clear inside the file” is printed **once per entry**, as a `.hint`
     under the first unprotected field — not once per field. Repeating a warning per row is how a
     warning becomes wallpaper.
8. **Attachments**, **history**, **actions** — structure unchanged; restyled to the tokens. The
   action row keeps the ladder: entry `rm` is `.sec-btn.danger`, separated by the rule and the
   “Destructive” eyebrow, exactly as §7.2.

---

## 11 · Accessibility, as a design constraint

### 11.1 Contrast

§2.6, computed, **zero failures** against AA text (4.5:1) and non-text (3:1). The current palette's
one systemic failure — every control boundary at 1.51 / 1.60 — is fixed by the `--sec-line` /
`--sec-edge` split (§2.5).

### 11.2 Focus

**Do not regress the focus ring.** Measured from the keyboard: eight Tab presses, eight real
controls, `:focus-visible` true on all eight, an identical computed ring on all eight
(`2px solid rgb(0,102,204)`, offset 1px). No rule in `secrets.css` sets `outline: none` and none may.

Two changes only:

```css
:focus-visible { outline: 0.125rem solid var(--sec-focus);   /* was 0.15rem */
                 outline-offset: 0.125rem;
                 border-radius: var(--sec-r-1); }
```

`0.15rem` computes to 2px in Chromium by rounding; `0.125rem` **is** 2px, so Firefox and WebKit —
which the research did not measure — get the same ring rather than 2.4px. And the ring gets its own
token, `--sec-focus`, so a future palette change cannot silently take it below 3:1 (measured
4.97–5.57 light, 8.02–10.07 dark).

### 11.3 Focus order, and meaning without colour

Focus order is DOM order everywhere. `#sec-pane` follows `#sec-main` in the DOM in **both** layouts,
so the visual order and the reading order are the same thing at every width — §1.1.

Everything that means something, and its non-colour carrier:

| Meaning | Non-colour carriers |
|---|---|
| selected row | `--sec-sel` tint + 3px inset accent bar (5.57 / 8.02) + `aria-current="true"` + label at `--sec-fw-med` |
| expired entry | `⚠` glyph + “Expired” chip **word** + `aria-label` suffix |
| access class | the **word** “Administrator” / “Yours” |
| read-only, not writable, keyed, key file, agent | the **word** in every case |
| unreachable | the word + the helper's own sentence as visible text |
| sort direction | `▲`/`▼` glyph **and** `aria-sort` |
| pane open / closed | `aria-expanded` |
| agent hold | the word “Unlocked” + a key glyph + running numerals |
| reveal deadline | running numerals (the bar is the *second* carrier) |
| strength | the bits number + the verdict **word** + a glyph |
| breach | `✕`/`✓` glyph + the word |
| password strength segments | count of lit segments (a quantity, not a hue) — §13 |

### 11.4 Tap targets

Measured today: 20 focusable controls on the safes list, all ≥ 24 × 24 — but the unlock dialog
contains a **23.9 × 47.6 px “Show”** button, which fails WCAG 2.5.8 (AA), and it is the smallest
target in the whole product sitting in the one dialog that must be usable while typing blind. Two
native `input[type=file]` controls render at **21px**.

```css
.sec-btn        { min-block-size: 2rem;   padding: var(--sec-s-2) var(--sec-s-3); }   /* 32px */
.sec-btn.tiny   { min-block-size: 1.5rem; padding: var(--sec-s-1) var(--sec-s-2);
                  font-size: var(--sec-fs-sm); }                                      /* 24px */
.sec-iconbtn    { min-inline-size: 2rem; }
.sec-field input, .sec-field select, .sec-field textarea { min-block-size: 2rem; }
```

`min-block-size` rather than tuned padding, because it is deterministic and does not depend on the
font's metrics.

**The file input is the one control CSS may not be able to lift.** Specify: apply
`min-block-size: 2rem`, **measure it live**, and if Chromium's native control ignores it, replace it
with a `.sec-visually-hidden` `<input type="file">` plus a real `<button>` that forwards `.click()`
and a `.sec-file-name` line showing the chosen file. **Report which one shipped** — do not leave it
ambiguous.

Nothing here reaches WCAG 2.5.5 (AAA, 44 × 44) and nothing is expected to; Cockpit's own controls do
not either, and a 44px minimum inside a 384px pane would halve what fits. Stated so it is a known
gap, not an oversight.

### 11.5 Zoom and narrow widths — the assertions

Today's page passes 1.4.10 at 200% (`scrollWidth 700 === clientWidth 700`) and is clean at 480 and
360. The new layout must keep that. Required live assertions:

1. At a **700 × 480** CSS viewport (the WCAG-correct way to emulate 200%, not a screenshot filter):
   frame `scrollWidth === clientWidth`; the pane is un-docked; `#sec-refresh` and `#sec-pane-toggle`
   are both on screen.
2. At **1400** window (frame 1160 = 72.5rem): `#sec-workspace` computes **two** grid columns and
   `#sec-pane` is at least `24rem` wide. *This is the assertion that would have caught the original
   three-pane defect and did not exist.*
3. At **480** and **360**: frame `scrollWidth === clientWidth`, zero elements wider than the frame,
   and the entries table still scrolls inside `.sec-scroll` (`scrollWidth > clientWidth` on the
   wrapper is expected and correct).
4. Tab from the top of the page: every stop has `:focus-visible` true and a computed
   `outline-width` of `2px`.
5. `securitypolicyviolation` count is **0** for the whole run.

---

## 12 · What this breaks in the test suites, and the migration

The suites select on class names, so the class names are part of the contract. **Kept unchanged on
the new markup:** `.sec-safe` (30 uses) on the `<tr>`, `.sec-safe-id` (25) on the id text,
`.sec-modal` (309), `.sec-alert` (43), `#sec-safes`, `#sec-detail`, `#sec-entries`, `#sec-sub`,
`#sec-alerts`, `#sec-live`, `#sec-banners`, `#sec-tree`, `#sec-browse-view`, `#sec-safes-view`,
`#sec-modal-host`, `#sec-agent-banner`, `#sec-refresh`, `#sec-lock`, `#sec-clip`, `.sec-value`,
`.sec-strength`, `.sec-breach`, `.sec-danger-block`, `.sec-path`, `.sec-kv`, `.sec-empty`.

Two things genuinely move and must be migrated rather than worked around:

**1. `#sec-sub` must keep its text contract.** `live-harness.js` `openPlugin()` waits for
`#sec-sub` to stop reading `/^loading/i` — that is how the whole live suite knows the page has
started. **Do not delete it and do not change what it says.** It stays in the topbar, restyled to
`--sec-fs-sm` `--sec-sub`; the pane's “nothing selected” state (§6.1a) repeats the same three facts
in a readable form.

**2. Action buttons leave the row.** The suites do

```js
'.sec-safe:has(.sec-safe-id:text-is("lab-dc")) button:text-is("Unlock…")'
```

in `live-ui.spec.js` (via the centralised `safeCard()` helper at lines 99–103) and inline at roughly
eight places in `ui.spec.js`. Under R3 the actions are in the pane, so this selector stops resolving.

**The migration is a selector change, not a weakened assertion.** Add one helper to each spec:

```js
/* Select the safe with this id and return the details pane showing it. */
async function openSafe(frame, id) {
    await frame.click(`.sec-safe:has(.sec-safe-id:text-is("${id}")) button.sec-rowdoor`);
    const pane = frame.locator("#sec-pane");
    /* STRONGER than what it replaces: proves the pane is showing the safe we asked
       for. Unlocking the wrong safe is a real error and nothing asserted this before. */
    await expect(pane.locator(".sec-safe-id")).toHaveText(id);
    return pane;
}
```

then `(await openSafe(frame, "lab-dc")).locator('button:text-is("Unlock…")').click()`.

Every call site becomes shorter **and** gains an assertion it did not have. Note that plainly in the
commit: this is a migration that strengthens the suite, and if any assertion ends up weaker than
before, that is a defect in the migration, not an acceptable cost.

**New tests this design requires** (none of them replace an existing one):
- theme mirror, both defect states, plus the shell-class canary — §3.4;
- `cockpit.permission` `changed` in both directions, with an admin safe selected — §4.4;
- the R1 count note in all three states, asserting **no id, label, format or path** appears while
  safes are hidden;
- the column chooser: Path off by default, on after toggling, gone again after reload (which is what
  proves §9);
- pane focus behaviour, each row of the §6.4 table;
- layout assertions 1–5 of §11.5;
- the palette gate of §14.

---

## 13 · The strength meter, the entropy readout and the countdowns

Read against the `dataviz` skill: the form is chosen first, colour last, and colour is validated
rather than eyeballed.

**This is not a chart.** It is a **hero number with a supporting magnitude mark** — the precise thing
the helper said is a number of bits, and a five-segment bar has five states for a continuous
quantity. So the number leads.

The widget, in order:

1. **The headline number.** `**62** bits` — digits at `--sec-fs-h3`, `--sec-fw-med`, `tabular-nums`;
   the word “bits” at `--sec-fs-sm` `--sec-sub`. This is the most precise thing on the widget and it
   goes first.
2. **The magnitude track.** Five segments, `flex: 1 1 0`, `2px` gap (the skill's surface-gap rule
   between adjacent fills), `--sec-r-1`, `0.3rem` tall. Lit segments are **one hue** — `--sec-accent`.
   Unlit are `--sec-line`.
   **Judgement call, and the alternative:** today the segments are green/amber/red by verdict. A
   red-to-green bar makes the *bar* the message, and the bar is the least precise mark in the widget;
   it also hands the entire message to hue. Single-hue means the bar answers “more or less” and the
   chip answers “is that enough”, which is the honest decomposition. If the operator prefers the
   traditional look, it is one rule — restore `.on/.warn/.bad` to `--sec-ok`/`--sec-warn`/
   `--sec-danger` — and the chip in (3) keeps colour from being the only carrier either way.
   Segment thresholds come from the helper's own scale (`categoryScale()`) whenever it publishes one.
   Fallback only, when it does not: 1 / 2 / 3 / 4 / 5 lit at < 28 / < 36 / < 60 / < 80 / ≥ 80 bits.
3. **The verdict chip** — status colour **and** a glyph **and** a word, all three, always:
   `⚠ Weak` (`--sec-warn`), `● Fair` (`--sec-sub`), `✓ Strong` (`--sec-ok`).
4. **Named weaknesses** — a `<ul>` at `--sec-fs-body` (raised from today's `0.82rem`), `--sec-warn`,
   each item one sentence from the helper, **verbatim**. These are the actionable part; they must not
   be the smallest text in the widget, which is what they are today.
5. **Breach — a separate line, never merged into the verdict.** A password found in a breach corpus
   is not “weak”, it is **known**, and the two must not share a mark.
   `✕ Found in a breach corpus` in `--sec-danger` `--sec-fw-med`; `✓ Not found` in **`--sec-sub`, not
   `--sec-ok`** — *judgement call:* “not found in the corpus we asked” is an absence of evidence, and
   painting it green overstates what the helper actually said.

No legend and no tooltip: one series, named by its own heading, which is the skill's rule for a
single series. No hover layer — there is nothing to reveal that is not already on screen.

Colours used: `--sec-accent` for magnitude; `--sec-ok` / `--sec-warn` / `--sec-danger` reserved for
status and never reused as “series colours”. Contrast for every one of them against every surface it
lands on is in §2.6.

**The reveal countdown, the clipboard countdown, the upload progress bar and the lockout countdown
all use the same treatment** (§7.4): one hue, `--sec-remain` custom property, tabular numerals,
transitions gated behind `prefers-reduced-motion: no-preference`, and the last five seconds in
`--sec-danger` with the numeral as the text carrier. Four deadlines that look like four different
things is four things to learn.

---

## 14 · Acceptance — how the implementer knows they are done

Mechanical gates, each of which is a command:

1. `./run_tests.sh` — 20/20, unchanged.
2. `./validate.sh` — all green. In particular the I11 ban still passes with `theme.js` present:
   `grep -REn '\b(localStorage|sessionStorage|indexedDB|document\.cookie)\b' *.js` must be empty.
3. **The rename is complete.** The old token names must be gone:
   ```
   grep -c 'var(--sec-\(card\|code-bg\|border\|err\|err-bg\|bg\|shadow\)\b)' secrets.css secrets.js
   ```
   must be **0**. No compatibility aliases — an alias outlives its purpose and hides an unconverted
   rule. (There are 51 references to rename; all of them are in `secrets.css`, because `secrets.js`
   contains **zero** `var(--sec-…)`.)
4. **The spacing scale is honoured.** Every `rem` length in `secrets.css` is one of the six
   `--sec-s-*` values, `--sec-pane-w`, `--sec-fs-*`, or a border/track width. Grep for surviving
   literals and justify each survivor in a comment.
5. **The palette is re-validated after any colour change.** Keep the contrast script beside the
   palette and re-run it; **zero failures** at 4.5:1 text and 3:1 non-text is the threshold and it
   does not move.
6. The live suite passes, with the new tests of §12 added and the `openSafe()` migration applied.
7. `securitypolicyviolation` count is 0 in every live spec.
8. Screenshots in `tests/browser/artifacts/` for: light docked, dark docked, un-docked at 700,
   360, the unlock modal in both themes, the pane in each of its four states, and the R1 note in
   states A, B and C. **The operator's `pwsafe3` must appear in none of them** — assert
   `!/pwsafe3/.test(document.body.innerText)` before every capture, as the research pass did.

---

## 15 · What we deliberately did NOT do

1. **Link `../shell/shell.css`.** 126 KB gz for ~45 values; it imports PF6's element reset (measured:
   h1 24→36px, h2 24→28px, h3 16.8→24px, body `#ffffff`→`#f2f2f2`, `box-sizing`
   `content-box`→`border-box` on every element) that we would then have to re-assert; and it couples
   this page's appearance to whatever PF version the host ships. Copying the values costs nothing and
   couples to nothing. §2.1.
2. **Link `../../static/branding.css`.** Measured: 338 bytes, three rules, **zero** custom properties,
   two id selectors we do not use. It buys nothing unless we render Cockpit's distro badge — and
   rendering another product's brand mark on our page is exactly the failure mode this design exists
   to avoid.
3. **Read `localStorage["shell:style"]`** the way `wireguard.js` and `headscale.js` do. It is the
   sibling idiom and it works, but `validate.sh` bans the identifier lexically and the live suite
   fails on any storage key that moves. Reading the parent's resolved class is also *better*: no
   re-derivation of `auto`, no possible disagreement with the shell, and it survives a browser with
   site data blocked, where `getItem` throws. §3.2.
4. **Persist the pane state or the column selection.** §9. With the correct escape hatch named
   (a helper-side `ui-prefs` verb), so the trade can be revisited without reopening the ban.
5. **Use PF's `border--color--default` for control boundaries.** `#c7c7c7` on `#ffffff` is
   **1.70:1** — PatternFly fails WCAG 1.4.11 in light mode, and matching it would import the failure.
   Split into `--sec-line` (decorative, PF's value) and `--sec-edge` (3.51 / 3.13 light, 5.77 / 7.24
   dark). §2.5.
6. **Use PF's light warning colour `#dca614`.** 2.3:1 on white. Kept a darkened amber at 6.85:1.
7. **A filled red destructive button, anywhere.** §7.2, with the one stated exception inside a
   rung-3 modal after the id has been typed.
8. **A hamburger glyph on the pane toggle.** §6.3 — the only place this design overrides a stated
   requirement, with the reason and the one-line revert.
9. **A red-amber-green strength bar.** §13 — with the reason and the one-line revert.
10. **Live links in entry detail.** A URL in a safe is attacker-controlled data (A3); rendering it as
    an anchor lets a safe's contents navigate the operator's browser. §10.2.
11. **Truncation with an ellipsis, anywhere.** Everything wraps, or scrolls inside its own
    `overflow-x: auto` box. A truncated safe id, path or URL is a value an operator can mis-identify
    or fail to copy, and mis-identification here means opening the wrong safe.
12. **Icon fonts, sprite sheets, `content: url()`.** Every glyph is either a real character in the
    text run with a visually-hidden word beside it, or an inline `<svg>` built by JS using
    `currentColor`. No new asset, and nothing that could become a CSP question.
13. **A slide-in animation for the pane, or any animation beyond a countdown's smoothing and a chip's
    colour fade.** A 400ms slide on every row click is 400ms of waiting, and it would have to be
    removed under `prefers-reduced-motion` anyway — so the design would be tuned for the case we do
    not ship.
14. **A “remember this pane/column/theme” setting of any kind**, and **any** relaxation of I9, I10 or
    I11. The one JS→CSS channel opened is `setProperty` of a single custom property, which the brief
    names as the preferred form.
15. **Any change to a verb, a request shape, an access check, or what `safeReachable()` decides.**
    In particular the rule that an **admin-class safe is never marked unreachable** from an
    unescalated `list` is preserved exactly as written; it is the fix for the bug that once made the
    default access class permanently unopenable, and a restyle is the easiest possible way to
    reintroduce it. §5.4.

---

## 16 · Risks, and what is still unmeasured

Honest list. Each one names what to measure and what happens if the measurement goes the other way.

| # | Risk | If it goes the other way |
|---|---|---|
| 1 | **PatternFly renames or inverts the dark class.** The regex `pf-(v\d+-)?theme-dark` covers a version bump, not an inversion (a `theme-light` class on a dark default). | The §3.4 canary test fails loudly the first time it happens, which is the point of it. The fallback is still `prefers-color-scheme`, so the page is wrong in the same two states it is wrong in today — no worse than the status quo. |
| 2 | **Firefox and WebKit are unmeasured.** Everything here was measured in the cached Playwright Chromium (headless, `--no-sandbox`, self-signed cert accepted; no `--disable-web-security` and no CSP flag). | `window.parent` same-origin access and `MutationObserver` are universal, so the risk is low. The two things that could differ are the computed `outline-width` (addressed by using `0.125rem`) and custom-property enumeration in `getComputedStyle` (addressed by requiring `getPropertyValue` in tests, §3.4). |
| 3 | **The native `input[type=file]` may ignore `min-block-size`.** Measured at 21px today. | The fallback is specified in §11.4 — visually-hidden input plus a real button. **Measure it and report which shipped.** |
| 4 | **The token values are a Cockpit 360 snapshot.** They moved between PF5 and PF6 and will move again. | The page looks slightly dated, not broken — which is the correct failure mode and is why we copied values rather than linking a bundle. |
| 5 | **The `cockpit.permission` `changed` path is reasoned code today**, because `harness.js` stubs `addEventListener` as a no-op. R1 makes it load-bearing. | §4.4 requires live tests in both directions before R1 ships. Shipping R1 without them would make the page's *most* visible behaviour its *least* tested. |
| 6 | **Most of the UI was never measured for contrast, size or tap targets.** The research covered the safes list, the topbar, the footer and the unlock dialog. **Not** measured: the agent banner, the entry-detail key/value grid, the reveal countdown, the export/upload/create/delete dialogs, the backups view, the conflict banner, and the generated forms for all 41 verbs. The smallest control found (23.9px) came from the one dialog that *was* opened. | Expect more sub-24px controls in the dialogs nobody opened. The `min-block-size` floors in §11.4 are written as blanket rules on `.sec-btn` / `.sec-btn.tiny` / form controls precisely so they fix the unmeasured cases too — but a sweep of every dialog is still owed, and it should be a test, not a look. |
| 7 | **No card was ever rendered for an imported, user-class, `psafe3` safe owned by the signed-in operator** — the exact row the operator looks at every day — because `pwsafe3` was correctly never touched. | The `dummy-fake-user-*` throwaways are the nearest proxy. The row and pane specs here are format- and origin-agnostic by construction (every field is drawn from the registry row or the probe, and the three path sentences in §6.1b cover the user-under-home case explicitly), but the first real sight of it should be the operator's, and any surprise there is a design bug to report, not to work around. |
| 8 | **The `copyValue` countdown change (§7.4) touches behaviour, not just style.** | It is small and it is testable: assert `#sec-clip` stays hidden after “Copy path” and appears after a value copy. If it turns out some caller depends on the current blanket arming, keep the blanket behaviour and say so — do not quietly leave both. |

---

## 17 · Files this design touches

| File | Change |
|---|---|
| `docs/DESIGN.md` | this document (owned by the design pass; nothing else was written) |
| `theme.js` | **new** — §3.2, ~40 lines |
| `index.html` | `theme.js` first in `<head>`; the `#sec-workspace` / `#sec-pane` skeleton; the pane toggle; the second skip link |
| `secrets.css` | the token layer; the rename (51 references); the table, pane, state, ladder, chip and countdown rules |
| `secrets.js` | `renderSafes` → table; `safeCard` → pane; the pane controller; the column chooser; R1 in the `permission` listener; `--sec-remain` and `--sec-depth` instead of the five direct `.style.*` width/padding assignments; `copyValue(value, {secret})` |
| `install.sh` | **must install `theme.js`** — the one step whose omission silently produces an unthemed page |
| `tests/browser/live-ui.spec.js`, `ui.spec.js` | the `openSafe()` migration (§12) and the new tests |
| `tests/browser/live-registry.spec.js`, `live-access.spec.js` | **added in 0.5.1** — §12 under-counted; all three live specs click Unlock from a card, so all three needed the pane idiom (§18.7) |
| `tests/root/20-verify-install.sh` | **added in 0.5.1** — it restates the package payload, so a design that adds a file to the payload touches it (§18.3) |


---

## 18 · As built — where the implementation diverged from this plan, and why

Written after the restyle was installed on this host and driven against the live
Cockpit 360, and **revised for 0.5.1**, which closed the five things 0.5.0's own
verification said were still wrong. Everything below is measured;
`docs/LIVE-WALKTHROUGH.md` carries the commands and the raw numbers, in a 0.5.0
section and a 0.5.1 section.

The rule for this section: a divergence is recorded whether it was a good
decision or a bad one, and the ones that are still **defects** say so in those
words rather than being written up as trade-offs. **A subsection that has since
been closed keeps its original finding and says what closed it** — deleting the
finding would delete the reason the fix exists, and the next person to look at
`overflow-wrap` or at `PLUGIN` needs the finding more than the fix.

### 18.1 R5 — not delivered in 0.5.0, delivered in 0.5.1

**As found (0.5.0).** §5.6's Path column and §6.1's "the path is ALWAYS in the
pane, in full" were both unreachable. Not mis-styled: unreachable, because the
data did not exist. The `list` verb's declared response was

```
[{id,label,format,access,mode,locked,reason,usable,password_required,
  needs_keyfile,agent_enabled,export_allowed,registry,origin,manageable}]
```

with no `path`, and live every safe returned `path` absent at both access
levels. Both halves of R5 were guarded on that field — `optColAvailable()`
offers the column only when some row has a path, and the pane's section is
behind `if (safe.path)` — so the checkbox was never offered and the section
never rendered. The plan assumed a field the helper does not publish and never
said to check.

Measured again from the shipped helper before anything was changed:
`/usr/local/sbin/secrets-admin list` returned exactly 15 keys per row and no
`path`; driven live as `cptestadm`, *any row carries path* was false, *Columns
offers a Path box* was false, and the pane drew only `["File header"]`.

**What 0.5.1 did.** `v_list` now publishes `path`, taken from
`resolve_entry(entry, ctx.ident)["path"]` — the same resolution the open path
uses, so there is no second source of truth and `%u` is expanded from kernel
identity and never from the request. The `list` verb's schema declares it. The
page needed no change: both guards simply became true.

**AND THE PRESCRIPTION THIS SECTION GAVE WAS WRONG.** This section used to say
"**The fix is in the helper**: add `path` to `list`'s response and populate it,
gated on access class". That was implemented, gated exactly as written, and it
passed every unit and integration gate — and then **failed live for exactly the
safe R5 was written about**: with administrative access ON, the pane for the
system safe `dummy-fake-safe` still drew no Path section.

The cause is structural and is not a bug: `secrets.js` calls
`callOnce("list", {}, false)` — `list` is spawned with **no superuser option,
always**, by design (the verb matrix at `secrets.js:3190`: `list` names what
exists; whether a safe may be OPENED is decided per verb). So the euid asking is
never root, and a class gate refuses every admin-class row at *both* access
levels. A gate whose effect is "the requirement is never met" is not a gate, and
the gating was withdrawn rather than shipping half of R5.

**What makes publishing it safe is a property of the LOADER, and it was
measured rather than assumed.** `list` runs at the caller's own euid, and a
registry file that euid cannot open is recorded as a registry error and never
becomes a row (`chmod 000` over an entry → `unreadable (EACCES)`, id gone from
`list`). The system registry is 0755/0644 root-owned policy — verified:
`/etc/cockpit-secrets/safes.d/dummy-fake-safe.json` is 0644 and any account can
read its `path` — and the per-user registry is only ever read out of the
caller's OWN home. **Every row therefore came from a file the caller could
already read, and `path` is a field of that file.** The disclosure is zero, not
mild. The residual mildness — home-directory names, filesystem layout,
screenshots — is precisely what R5's off-by-default column and its deliberate
pane answer, and §5.6's three reasons stand unchanged.

Four rules, checked and documented in `docs/CONTRACT.md`:

| case | `path` | why |
|---|---|---|
| `mode: "ro"` | published | read-only is about writes, not about naming the file |
| the file has vanished | published, nothing stats it | so it is not an existence oracle |
| a per-user entry shadowed by a system id | the SYSTEM entry's path | the loader drops the shadowed row entirely (C4 rule 5), so what is shown is the file that would actually be opened |
| a `%u` entry that cannot be resolved for this caller | **omitted** | an unexpanded `%u` names no file; the key is left out rather than filled from the raw entry |

**Verified live**, as `cptestadm`, against the installed helper: unescalated,
the per-user row carries
`/home/cptestadm/.local/share/cockpit-secrets/safes/dummy-fake-user-kdbx.kdbx`;
unescalated, the admin-class row is `usable:false` and **still** carries
`/etc/cockpit-secrets/safes/dummy-fake-safe.kdbx` — the value a class gate would
have withheld. Escalated, the Path column shows both, the pane shows both in
full with the correct location sentence, and the column is off on first load.
`live-ui.spec.js` **item 11** is the committed regression test, and it drives
both registries in one escalated session.

**Watched failing with the fix reverted:** the pre-change helper
(`git show HEAD:secrets-admin`, sha `68d62ca4…`) was temporarily installed and
the live page re-driven — *any row has path* false, Path checkbox not offered,
pane sections `["File header"]` only. Restored immediately; `./install.sh`
reports 0 changes against the source.

### 18.2 R1 works; the mechanism §4.4 specifies does not run

§4.4 designs a `cockpit.permission` `changed` listener that locks, wipes,
clears the pane and moves focus. Measured across a real escalation, counting
navigations of the plugin document alone: **Cockpit's shell reloads the plugin
frame when superuser status changes** (1 navigation, `performance.timeOrigin`
moved, an injected canary gone).

The operator-visible behaviour §4.1 asks for is delivered — the row appears and
disappears with no manual refresh, the selection clears, the pane empties — but
`elevationChanged()` is not what delivers it in the escalation direction and is
still unexercised. A frame reload destroys the session outright, which is a
stronger guarantee than the listener's, so this is not a security gap; it is a
piece of code that is not reached and should not be described as tested.

### 18.3 `theme.js` was never actually installed — fixed in 0.5.1

**As found (0.5.0).** The guarded second resolver in `secrets.js` carried the
whole feature on an installed host: with `theme.js` **absent**, the frame still
resolved `sec-light` / `sec-dark` correctly in both directions, live, with no
reload. §3's mechanism is sound and the duplication was the right call.

But `index.html`'s comment claimed the missing file "404s silently". It does
not: Cockpit answers with an HTML error page and Chromium logs

```
Refused to execute script from '…/theme.js' because its MIME type ('text/html')
is not executable, and strict MIME type checking is enabled.
```

on **every page load**, which is what failed `live-ui.spec.js` item 1.
Reproduced against the installed page: four console entries attributable to the
package, three of them `theme.js` — a 404, the MIME refusal, and a
`requestfailed` with `net::ERR_ABORTED`. `securitypolicyviolation` events: 0, so
the failure was never a policy problem. On disk, `/usr/share/cockpit/secrets/`
held exactly four files.

**The cause was one array element.** `PLUGIN` in `install.sh` is the copy list
AND the list the package directory is swept down to, so the installer copied
`theme.js` in section 1 and deleted it again in the sweep on the same run,
every run — while the same script's pre-flight syntax-checked it.

**What 0.5.1 did, and why it is INSTALL rather than delete-the-reference.** The
choice turns on whether the page genuinely needs the file, so that was measured
rather than argued. Driving both builds through the real shell with `secrets.js`
delayed 3 s (standing in for a cold cache or a slow link):

```
theme.js absent   frame paints at 161 ms with <html class="">  -- theme UNRESOLVED;
                  the guarded resolver in secrets.js does not run until 3068 ms
theme.js served   class is on <html> at 141 ms, first paint 169 ms
```

On an unthrottled load the same asymmetry is visible but small (238 ms vs
144 ms), which is exactly why it was not caught: the fallback's window is
bounded by the size of `secrets.js` and the speed of the link, and it happens to
win on a fast loopback. The fallback is a **correctness** guarantee; it is
structurally incapable of being a **first-paint** one, because it is deferred
behind 476 KB while `theme.js` is a 4 KB blocking script the parser must run
before `<body>` exists. That is §3.3's "no flash by construction rather than by
timing", and it is the only path that delivers it.

So: `PLUGIN=(manifest.json index.html secrets.js secrets.css theme.js)`, and —
the part that makes it un-repeatable — **a new pre-flight gate**. What `PLUGIN`
could disagree with was never the sweep; it was `index.html`. The gate parses
the page with `html.parser` (not a regex over HTML), collects every attribute
that makes the browser fetch a second file from the package directory
(`script/img/iframe/audio/video/source/embed/track @src`, `link @href`,
`object @data`), discards anything with a scheme, an authority, an absolute path
or a parent segment (so `../base1/cockpit.js` is correctly Cockpit's, not ours),
and **dies** if a package-local reference is not in `PLUGIN`. It refuses a
subdirectory reference outright, since the payload is flat. It refuses rather
than warns: nothing is written at that point, the fix is one word, and a warning
is precisely what the previous round produced and nobody acted on. Live output:

```
index.html: 3 package-local reference(s), every one of them installed (theme.js, secrets.css, secrets.js)
```

**Watched failing with the fix reverted:** the gate run against `index.html`
with `theme.js` removed from `PLUGIN` exits 1 naming the file and the element;
with it present, exit 0. Edge cases exercised separately — `../base1/cockpit.js`,
an absolute `/base1/x.js`, an `https://` CDN and a `data:` URI are all correctly
ignored; `assets/favicon.png` is correctly refused.

**And one claim in the 0.5.0 text of this section was itself wrong.** It said
"§17 should have listed `install.sh` as a file this design touches; it did not."
§17's table **does** carry an `install.sh` row, reading "**must install
`theme.js`** — the one step whose omission silently produces a page with no
theme at all". The design flagged the step and the step was still missed, which
is the argument for a gate rather than for better prose.

Console on the installed page after the fix, driven through the real shell as
`cptestadm`: **0 console errors from the package, 0 `securitypolicyviolation`
events**, and all four package resources answered 200. The one remaining
`requestfailed` on a package URL is proven not to be ours rather than assumed:
`net::ERR_ABORTED`, `nav=true`, `type=document` — a cancelled navigation,
identical in kind and flags to Cockpit's own six for `/system/index.html`,
`/system/services.html` and `/updates/index.html` in the same page load.

**One consequence in a file this design does not own.** `tests/root/20-verify-install.sh`
restated the payload as four names and therefore failed the release that
legitimately grew it to five. Fixed in 0.5.1 by deriving `want_pkg` from
`install.sh`'s `PLUGIN` line instead of restating it — a hard gate carrying its
own copy of a list is a gate that fails the wrong thing.

### 18.4 §2.6's contrast table is right; the first measurement of it was not

Recomputed from the rendered page rather than from the plan: **21 distinct
fg/bg pairs in light and 23 in dark, zero below threshold**, lowest actual
ratios 4.97 and 6.66.

An initial pass reported two failures per theme (`Save` 2.25/3.33, `Previous`
2.52/2.94). Both are `disabled: true`. **WCAG 1.4.3 exempts inactive user
interface components**, so a contrast audit that does not read the disabled
state reports false failures. Recorded here because §11.1 does not mention the
exemption and the next person to measure this will hit it too.

### 18.5 What §11 promised and the page delivers

* 18 tab stops inside the frame, all `:focus-visible`, all `2px solid`, one
  distinct outline width — §11.2 as written.
* §11.5's assertions hold: at the 700 × 480 zoom viewport,
  `scrollWidth === clientWidth` and **zero** elements overflow outside their own
  scroller; at 360px the table scrolls in its own box while the page does not.
  **Corrected in 0.5.1:** that last clause was true of the SAFES view and false
  of the ENTRIES view, where a visually-hidden span escaped its scroller and the
  page really did scroll sideways. §18.10 has the measurement and the one-line
  fix; it is now asserted by asking the page to scroll and reading how far it
  went, rather than by comparing `scrollWidth` — which is what missed it.
* `prefers-reduced-motion: reduce`, emulated: zero animating and zero
  transitioning elements.
* §11.4's tap targets: one stop is under 24 CSS px in one dimension — the
  footer's `<summary>` at 960 × 21. §11.4 does not carve out an exception for a
  full-width disclosure and probably should.

### 18.6 The layout numbers §1 predicted, measured on the installed page

`728px 384px` at a 1400px window (frame 1160px), pane at `x = 760` sharing
`y = 199.19` with main, `<aside role="complementary">` after `#sec-main` in the
DOM. Collapsed is `0 × 0` with the grid at one column and the table reclaiming
728 → 1128px. §1.1, §1.2 and §1.3 are as built.

### 18.7 The cost §12 under-counted

§12 anticipated a migration in `live-ui.spec.js`. In fact **all three live
specs** break, on one selector — `.sec-safe … button:text-is("Unlock…")` —
because `secrets.js:3969`'s "nothing in the row is an action" moved every action
into the pane. `live-registry.spec.js` and `live-access.spec.js` item 9 fail the
same way. §12 should have said "every suite that clicks Unlock from a card",
which is all of them.

**Migrated in 0.5.1**, on one shared idiom, because the restyle made an action
two gestures — choose the row, then use the pane — so that is what the suites
do. The hooks, and why these:

| thing | hook | why |
|---|---|---|
| row | `#sec-safes tbody tr.sec-safe` filtered on exact `.sec-safe-id` text | both classes were kept from the card markup for this; scoped to `tbody` because `.sec-safe-id` now appears in the pane too |
| door | `button.sec-rowdoor` | the row's real accessible control, not the `<tr>` |
| Unlock | `#sec-pane-body .sec-safe-actions button.sec-btn.primary` | STRUCTURE, not text: `safeActions()` builds exactly one primary control and it is Unlock, so this survives a change of wording |
| pane | `#sec-pane`, `#sec-pane-body`, `#sec-pane-toggle` | ids from the shipped `index.html` |

`selectSafeRow()` waits on the PANE showing that id, so a mis-aimed click fails
naming the safe instead of asserting about another one, and `paneOpen()` /
`setPane()` read and drive R4 from `aria-expanded`. `waitForSafeList()` now
waits for a STRUCTURE (a row, a `.sec-state h3`, or a `.sec-alert`) rather than
"any text not starting with Loading" — the old form is true of a host halfway
through `clear()`-then-append, and it made item 2 read `#sec-safes`.textContent
as `""` and fail four assertions about a panel `live-access` read in full a
moment later.

**Three assertions no longer make sense as written and were replaced, not
deleted**, each with its reason recorded in the spec: item 2's "class blocks in
document order" (`.sec-class-block` is gone; class is a column and "admin first"
is the table's default sort, so `aria-sort` plus row order carries it, and only
when both classes are visible); item 2's "cptest sees N unreachable safes" (R1
draws no admin row while access is off, and `safeReachable()` no longer calls an
admin-class row unreachable — the state is now reachable only via a user-class
safe the helper reports unusable, which does not exist on this host, and this
suite will not break a registered safe to observe a disabled button); and
`live-access` item 9's "the admin-class card offers Check this safe while access
is off" (genuinely unreachable — that control exists only for an admin safe
while access is off, and R1 hides the row in exactly that state; what the
assertion was ABOUT is still checked by driving the verb that control drives).

### 18.8 Divergences the implementer disclosed, confirmed as built

Each of these was declared in the implementation hand-off and is recorded here
as accepted:

* §13's hero-number DOM restructure was not done; the CSS half is. The meter's
  segments are single-hue — verified live, one lit segment at `password1` in the
  same blue as five at 289 bits — and the verdict is carried by the sentence.
* §10.2's "title as the pane heading" was not done; the heading stays `Entry`
  with the title beneath, to keep `#sec-detail h3` for the live suite.
* §4.3's argument against a standing warn alert was not taken; the escalation
  banner stays a warn alert, with the count note added rather than substituted.
* `.sec-safe.unreachable` no longer dims. Confirmed as the better choice, and
  confirmed as the reason `live-ui` item 2's unreachable check now fails.
* The agent banner still names an admin safe while admin safes are hidden. I18
  outranks R1's cosmetic hiding; correct as built.
* `min-block-size: 2rem` does lift the native file input to 32px, so the
  visually-hidden-input fallback was not needed and did not ship.

### 18.9 The entries table was cramped at the default docked width — fixed in 0.5.1

Found by **looking at a screenshot**, not by an assertion — none of the numeric
checks in §11.5 catches it, because nothing overflows and the page does not
scroll.

§5.5's mechanism works exactly as written. Measured in the browse view at a
1400px window with the pane docked:

```
#sec-entries host   504px      (1160 frame − 384 pane − tree column − gaps)
table               672px      min-inline-size: 42rem  ✔ as specified
.sec-scroll         overflow-x: auto, scrollWidth 672 > clientWidth 504  ✔
document            no horizontal scroll  ✔
```

So the "scroll inside its own box" behaviour is delivered and the
one-character-per-line collapse §5.5 was written to prevent does not happen.

**But 42rem is too small a floor for a seven-column table.** At 672px each
column gets ~96px, and with `overflow-wrap: anywhere` on every cell the first
row renders **five lines tall**:

| cell | width | lines |
|---|---|---|
| `build-01.example.com — shell` | 115px | 5 |
| `ada.lovelace` | 103px | 5 |
| `ssh://build-01.example.com/` | 92px | 5 |
| `work, servers, ssh` | 78px | 5 |
| `0` | 109px | 5 |
| `2026-09-07T00:22:42Z` | 107px | 5 |

`ada.lovelace` is a twelve-character string being broken mid-word in a 103px
column. With the pane closed (904px) it is still three lines. A 101px row height
for values this short is a legibility defect, and it is the *default* state of
the browse view — pane open is the documented default at ≥ 60rem.

Two things are wrong, and they are separable:

1. **The floor is too low.** Seven columns need roughly 56–60rem before the
   values stop fighting for space, or the table needs to drop columns at this
   width the way the safes table drops optional ones.
2. **`overflow-wrap: anywhere` is applied too widely.** It is the right rule for
   the URL column, which can hold a 300-character unbreakable token (the testbed
   has one on purpose). It is the wrong rule for Username, Tags, TOTP,
   Attachments and Modified, none of which can contain a token that overflows a
   sane column. Scoping it to Title and URL would stop `ada.lovelace` breaking
   at all.

Neither is a regression — the old three-column layout never rendered.

**Both were fixed in 0.5.1, and the numbers above were re-measured worse than
they are written here before anything was changed:** at a 1400px window with the
pane docked the first row was **26 lines / 552px** tall (it carries the
deliberate 254-character title), rows 2 and 3 were 5 and 6 lines, and all seven
columns resolved `overflow-wrap: anywhere`. Longest unbreakable token per
column, measured with a canvas in each cell's own resolved font: Title 160px,
Username 144px, URL 2126px, Tags 107px, TOTP 37px, Attachments 10px, Modified
161px. On `dummy-fake-user-kdbx` the Username column measured **103px** — the
exact number published above for `ada.lovelace` breaking mid-word.

**The floor: 42rem → 60rem, derived rather than chosen**, and the arithmetic is
written into `secrets.css` beside the rule:

```
 7 x 2rem cell padding the sheet already spends (2 x --sec-s-3)   = 14rem
 the six columns that may NOT break a word, each needing its
 longest unbreakable token or its own nowrap <th>, whichever is
 wider:  160 + 144 + 107 + 37 + 78 + 161 = 687px                  ~ 43rem
 URL — the one column allowed to break anywhere — still needs a
 line                                                             =  3rem
                                                                   -------
                                                                    60rem
```

Checked against reality rather than left as arithmetic: with the scoping below
in force the table's own min-content measures 944px, so the 960px floor sits
just above it — the floor decides the width instead of this safe's data, and the
two rules agree rather than one silently overriding the other. 60rem is already
a named number in the sheet's own budget list, so no new magic number entered
it.

**The wrap: `anywhere` → `break-word` on `table.sec td`, and the two are not
cosmetically equivalent.** `anywhere` lets a word be broken when MIN-CONTENT is
computed, so every column's minimum becomes one character and the auto layout is
free to hand a twelve-character username 96px. `break-word` contributes the
whole word to min-content, so the layout must give the column the width of its
longest word and the break cannot happen. `anywhere` is then re-applied to
exactly two places: `#sec-entries table.sec td:nth-child(3)` — the URL column,
whose 300-character token measures 2126px and would otherwise set the whole
table's min-content — and `#sec-safes table.sec td .mono`, the safes table's
Path and Id columns, which `safeRow()` gives a real `.mono` handle.

**The URL rule is addressed by POSITION and that coupling is pinned, not
hoped.** The renderer writes a bare `<td>`; there is no class, id or attribute
to address instead without editing `secrets.js`. `listColumns()` takes the order
from the helper's schema when it publishes `fields[].in_list` and from
`CONTRACT_LIST_COLUMNS` otherwise (this helper publishes no `in_list`, so URL is
third). `live-ui.spec.js` item 10 now **asserts that the third header reads
"URL"** and that its cells resolve `anywhere` while Username resolves
`break-word`, so a reordering schema fails loudly instead of the rule quietly
landing on the wrong column. If it ever did, the failure is degraded and not
broken: the table grows and scrolls in its own box. The clean fix is one class
in `renderEntries()`.

Result on `dummy-fake-safe`, 1400px window, pane docked (504px box): table
672 → **960px**, Username 96 → **176px** (its 144px token plus 32px padding, not
a pixel more), first row 26 → **9 lines**, rows 2 and 3 5 and 6 → 4 lines. On
`dummy-fake-user-kdbx` at all four widths the columns are
`[250,144,126,110,68,109,153]` and the tallest row is 4 lines, with the page
scrolling 0px at every one of them.

**Watched failing with the fix reverted:** a reverted `secrets.css` (42rem
floor, `anywhere` back on every cell, no `position: relative`) was installed and
`live-ui.spec.js` run unchanged — 118/123, item 10 FAIL, with the floor
assertion, the Username assertion, the every-other-column assertion and the
360px page-scroll assertion all red, and the reverted run reporting the Username
column at **103px**.

### 18.10 A second layout defect, found while measuring the first

Not in any brief, pre-existing, and invisible to every check §11.5 makes.

At a 380px frame the **entries** view already scrolled the PAGE sideways at the
old 42rem floor: `documentElement.scrollWidth` 450 vs `clientWidth` 380, and
`window.scrollTo(2000, 0)` actually moved it 70px. Widening the floor made it
698 vs 380 / 318px, which is how it was noticed. No element was outside its own
scroller.

Cause: `.sec-visually-hidden` is `position: absolute`, the entries table puts one
inside every boolean cell (the word "TOTP" beside the tick), and **nothing
between that cell and the document was positioned** — so those spans' containing
block was the INITIAL containing block, `.sec-scroll` never clipped them, and
`clip: rect(0 0 0 0)` does not remove an element from the root's scrollable
overflow. §18.5's "at 360px the table scrolls in its own box while the page does
not" was true of the safes view and **not** of the entries view.

The fix is one declaration — `.sec-scroll { position: relative }` — which makes
the scroller the containing block and brings the escaped spans back under its
clip. Measured at a 380px frame: 698/380 with `scrollX` 318 → 380/380 with
`scrollX` 0. It is load-bearing, not tidying, and the 360px assertion in
`live-ui.spec.js` item 10 is what says so: it goes red when the declaration is
removed.

### 18.11 What 0.5.1 leaves open

Recorded here because the point of §18 is that a closed list and an honest list
are different documents.

* **`ui.spec.js` did not grow a source-level assertion on the CSS.** The natural
  one is: `table.sec td` must resolve `break-word`, and the only `anywhere`
  inside a table must be the URL column and `#sec-safes .mono`. It already reads
  `secrets.css` for the motion gate, so the seam exists.
* **The safes table is cramped with every optional column on.** Measured with
  Path, Registry, KDF and Id all ticked: 8 columns in a 669px table, rows 28–30
  lines tall at a 700px frame and below. Nothing overflows and the page never
  scrolls, so it is the same class of defect as §18.9 — but its column count is
  variable by design (4 to 9) and its 30rem floor is right for the 4 it draws by
  default, so one wider number for all of them would be an unmeasured decision.
* **The `path`-less case (an unresolvable `%u` entry) has no committed test.**
  It is exercised only in a scratch registry under `unshare --map-root-user`.
  Neither is the backend-unavailable branch of `usable:false` — both formats are
  available on this host.
* **Chromium only.** No Firefox, no WebKit, in any round.
