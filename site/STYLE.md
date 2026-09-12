# hop website: writing & design philosophy

**Read this before editing anything in `site/`.** The site exists to take a
visitor who knows *nothing* about hop and get them to solving their problem in as
few words and steps as possible. Every change should be measured against that.

## The reader

Assume **zero prior knowledge**. The reader has never heard of hop. They arrived
with a problem ("I want to reach my home server without port-forwarding", "I want
a private network for my machines", "I want to reach my printer from the road").
They do not know our vocabulary and they will not read carefully; they scan.

## The eight rules

1. **Never use a term before you define it.** The first appearance of any hop
   concept must also introduce it in plain language. This applies to **warren,
   node, virtual IP (vIP), MagicDNS, member, host, gateway**, and especially
   **warren**. If a word like "warren" shows up in a comparison table or a heading
   before the section that explains it, that's a bug. Plant the plain-language
   idea first ("a private network for your machines"); reveal the name ("we call
   it a *warren*") at the section that owns the concept.

2. **Lead with the reader's problem, not our feature.** Section openers say what
   the reader gets ("Reach the things that can't run hop"), not what we built
   ("Tier-1 subnet routing"). The feature name, if any, comes after the benefit.

3. **Fewest words, fewest steps.** Cut every word that doesn't move the reader
   toward doing the thing. A copy-pasteable command beats a paragraph. If a
   sentence explains *how it works* rather than *how to use it*, it probably
   belongs in `docs/`, not the site.

4. **Three core jobs, three clear paths.** The site must make each of these
   findable and turn-key, in order of how common they are:
   - **Reach a machine:** shell in, run a command, copy/sync files.
   - **Set up a private network:** your machines reachable by name from anywhere.
   - **Expose a local device:** reach things on a LAN that can't run hop.
   A visitor should self-identify their job from a heading and get the exact
   command(s) without hunting.

5. **Concrete beats abstract.** Show real commands and real output. Use an
   obviously-generic placeholder host (`myserver`, `myserver.hop`) and treat it as
   a placeholder. **Never put a real internal hostname** (e.g. an actual machine
   name) on the site.

6. **Don't credit competitors for our features.** A factual comparison table is
   fine (and may name competitors). Outside the comparison, never say a feature is
   "based on", "inspired by", or "the X idea"; describe what it does on its own
   terms.

7. **Progressive disclosure.** Page head (what it is), the product in use,
   the feature rows, then the commands, then links out. Advanced options and
   jargon live in the docs, or behind an "Advanced" disclosure. Don't make the
   first screen carry concepts the reader hasn't earned yet.

8. **No em-dashes.** Don't use em-dashes (`—`) or `&mdash;` anywhere on the site.
   Use a colon when one part explains or lists the other ("One binary: install,
   invite, connect"), a comma for a quick aside, parentheses for a true
   parenthetical ("one machine (a home server, a Pi) carries the rest"), or just
   two sentences. The same goes for en-dashes in prose; a hyphen is fine in
   `compound-words` and ranges.

9. **Colours come from the palette, and text must pass WCAG AA.** Never hard-code
   a colour; use the `--color-*` variables in `shared.css`. Body text needs at
   least **4.5:1** contrast against its background (large/bold text 3:1). Two
   traps to know about:
   - **`--color-primary` (`#dc2626`) is not a text colour.** It measures 4.12:1
     on the page background and fails AA. It is correct as a *button
     background* (white on it is 4.83:1). For link and accent **text**, use
     `--color-link`.
   - **Every anchor needs a colour.** An `<a>` with no class and no colour
     falls back to the browser's default blue: off-palette and barely legible
     on `#09090b`. `shared.css` now sets a base `a` rule, and container
     anchors (`a.card`, `a.btn`, `a.nav-brand`) inherit instead of colouring
     their contents. If you add a new container-anchor pattern, add it there.

## The design system: every page is built from the same parts

The whole site is one narrow centred column (`.wrap`, 56rem) with a lot of
air and very little copy. It reads like a product page, not a manual. Every
page uses only these parts, all defined in `shared.css`:

- `.page-head`: an `h1` (two lines at most), a one- or two-sentence `.sub`,
  optionally a `.cta` row of buttons (`.btn-solid` for the one primary action,
  `.btn-ghost` for the rest) and a `.meta` line in mono.
- `.shot`: the product in use, straight under the head. A `.term` terminal
  with `.line` elements that fade in (`style="--i:N"`), or an SVG diagram.
  One per page, and only if it shows the product doing the thing.
- `.rows` of `.row`: a short bold label and one or two sentences. This is the
  feature list. Four or five rows, never more than two sentences each.
- `.sec` with an `h2` and a `.lede`: a section. Inside, use `.step-list` of
  `.stp` (numbered label plus `.cmdbox`), `.cols` for text beside a `.cmdbox`,
  `.plans` for link cards, `.tbl` for a comparison, `.qa` for questions.
- `.cmdbox`: a copyable command. Write the copy button empty
  (`<button class="copy-btn" data-cmd="..." onclick="copyCmd(this)"></button>`);
  `shared.js` fills in the icon.
- `.note`: small tertiary text, usually holding the link to the docs.

Do not add page-local CSS except for a genuinely one-off control (the install
command builder is the only case today). Do not bring back hero badges,
gradient text, icon cards, or a grid background.

## Site pages describe; docs explain

A site page says what the thing does and shows the commands. It never explains
mechanism, lists every option, or argues a case at length. That material lives
in `docs/product/` and the page links to it from a `.note`. When a page needs
more than one screen of prose, move the prose to the matching doc and leave a
sentence and a link:

- install options, platforms, verifying a download: `install.html`, with the
  distro table in `docs/product/overview.md`
- the private network, names, bridging a LAN, port forwarding:
  `private-network.html`, with the design in `docs/product/warren.md`
- AI agents: `agents.html`, with the bootstrap rationale and the cold-start
  eval in `docs/product/ai-and-scripting.md`
- fleet: `fleet.html`, with roles, sandboxes and scale in
  `docs/product/warren.md` and `docs/product/security.md`
- scheduled work: `orchestration.html`, with capabilities and scripts in
  `docs/product/data-and-automation.md`
- threat model: `security.html`, with the invite reference, crypto and the
  honest limits in `docs/product/security.md`
- the comparison table: `faq.html#compare`; the long form is `vs-tailscale.html`

If a page edit adds a paragraph, ask which doc it belongs in instead.

## Quick self-check before shipping a site change

- Could a stranger read top-to-bottom and never hit a word they weren't just
  taught? (Search the page for `warren`, `node`, `vIP`, `MagicDNS`; is each
  one's first appearance also its introduction?)
- For each of the three jobs, can the reader get the command in under ~20 seconds
  of scanning?
- Did I add words that explain *mechanism* instead of *use*? Cut them.
- Any real hostnames, or competitor "inspired-by" credit? Remove them.
- Any em-dashes? `grep -nE '—|&mdash;' site/*.html` must return nothing.
- Any hard-coded colours or low-contrast text? Run `./site/check-style.sh`; it
  fails on em-dashes, undefined CSS classes, anchors with no colour, and any
  text colour below WCAG AA.

After a copy change, redeploy with `./scripts/release.sh --site-only`.
