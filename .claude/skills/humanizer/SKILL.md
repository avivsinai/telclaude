---
name: humanizer
description: Audits text against AI writing tells and rewrites it into natural prose. Use when the operator wants drafted content de-AI-ified, especially before publishing on X/LinkedIn/Threads or sending to readers.
allowed-tools: []
---

# Humanizer

Audit a draft for the usual LLM tells, then rewrite it so a human reader can't pattern-match it as AI.

## When to Use

- Operator says "humanize this", "de-AI this", "make this not sound like ChatGPT", "rewrite in my voice".
- Before posting drafted content to X, LinkedIn, Threads, a blog, or sending to a reader.
- After another skill (social-posting, summarize) produces text that needs a final pass.
- Operator pastes copy and asks for an honest critique of how AI-flavored it reads.

Do not auto-invoke on raw conversational replies. The skill is for prepared drafts, not chat.

## Procedure

1. Read the entire draft once. Note the apparent voice (if any) and the audience.
2. Scan top-to-bottom for tells in the four groups below. Mark each hit.
3. Rewrite the draft applying the counter-patterns. Keep meaning, claims, numbers, and technical terms exact.
4. Return the rewrite, then a short change log: one line per tell category that fired, with the original snippet and the replacement.
5. If nothing fires, say so and return the original unchanged. Do not invent problems.

## Lexical tells — overused words and phrases

| Tell | Example | Rewrite pattern |
|------|---------|-----------------|
| "delve into" | "Let's delve into the data." | "Look at", "go through", "read", cut entirely. |
| "tapestry" | "a rich tapestry of ideas" | Drop the metaphor. Name the thing: "a mix of ideas" or just "ideas". |
| "ever-evolving" / "ever-changing" | "in this ever-evolving landscape" | Cut the modifier. Or: "as X keeps changing". |
| "in today's fast-paced world" | Stock opener. | Delete the opener. Start with the claim. |
| "navigate the complexities" | "navigate the complexities of compliance" | "deal with compliance", "handle compliance edge cases". |
| "leverage" (verb) | "leverage AI to" | "use", "apply", "run". |
| "synergy" / "synergistic" | "synergistic outcomes" | Name the actual mechanism, or cut. |
| "robust" / "robust solutions" | "a robust framework" | Say what makes it robust, or cut: "a framework that handles X". |
| "unprecedented" | "unprecedented growth" | Give the number. If you can't, drop the word. |
| "paradigm shift" | "a paradigm shift in how" | "a change in how", or describe the change. |
| "holistic approach" | "we take a holistic approach" | Say what you actually do across which axes. |
| "actionable insights" | "deliver actionable insights" | "things you can do next:" then list them. |
| "best practices" (as buzzword) | "industry best practices" | Name the practice. If you can't, cut. |
| "game-changer" / "revolutionary" / "transformative" | "a game-changing tool" | State the effect, with a number if possible. |
| "cutting-edge" / "state-of-the-art" | Marketing filler. | Say what's new about it. |
| "dive deep" / "deep dive" | "let's dive deep into" | "look at", "read through". |
| "underscore" / "underscores the importance" | "underscores the value" | "shows", "matters because". |
| "myriad" | "a myriad of options" | "many", "lots of", give a count. |
| "vibrant" | "a vibrant community" | Cut, or describe what makes it active. |
| "seamless" / "seamlessly" | "seamlessly integrate" | "fits into", "works with X without extra config". |
| "meticulous" / "meticulously crafted" | Self-flattery. | Cut. Let the work speak. |

## Syntactic tells — sentence and phrase structure

| Tell | Example | Rewrite pattern |
|------|---------|-----------------|
| Em-dash as default connective | "It's hard — but worth it — for teams." | Use a comma, a period, or parentheses. Reserve em-dashes for genuine asides. Limit to one per paragraph. |
| Tricolon (three parallel clauses) | "It's fast, it's safe, it's scalable." | Pick the strongest one. Or: two clauses, not three. Avoid rhythm that scans as a slogan. |
| "Not just X, but Y" / "It's not X — it's Y" | "Not just a tool, but a movement." | State Y plainly. Drop the X. |
| "Whether you're X or Y..." opener | "Whether you're a startup or an enterprise..." | Pick the actual audience. Cut the hedge. |
| Parallel "From X to Y" sweeping range | "From healthcare to finance" | Name the specific case you mean, or two concrete ones. |
| Hedging openers | "It's worth noting that…", "It's important to remember…" | Delete the opener. Lead with the noted thing. |
| Throat-clearing intros | "In this article, we'll explore…" | Cut. Start with the first real claim. |
| Conclusion announcers | "In conclusion,", "To wrap up,", "In summary," | Cut. The last paragraph is the conclusion by position. |
| Stacked transitions | "Moreover, … Furthermore, … Additionally, …" | One transition max per section. Prefer none. |
| "Not only X but also Y" | "Not only fast but also cheap." | "Fast and cheap." |
| Faux-conversational rhetorical Qs | "Sound familiar?" / "Ever wondered why?" | Cut, or replace with a direct statement. |
| Symmetric two-clause closers | "It's small, but it matters." | Vary the rhythm; sometimes end on the strong clause alone. |

## Rhetorical / voice tells

| Tell | Example | Rewrite pattern |
|------|---------|-----------------|
| Empty validation of the reader | "Great question!" / "You raise an interesting point." | Cut. Answer. |
| Over-qualification | "While there are many factors to consider, it's generally true that…" | State the claim. Add one qualifier if needed. |
| False balance / both-sides hedging | "On one hand X, on the other hand Y" with no commitment | Take a side, or admit you can't and say why. |
| Recursive restating | Says the thesis, restates it, restates again. | One statement. Move on. |
| Faux humility ("I'm just an AI" / "I may not have all the answers") | Self-referential disclaimers. | Cut. If a limit is real, name it specifically. |
| Performative enthusiasm | "I'm thrilled to share…" | Cut the frame. Share. |
| Universal claims | "Everyone knows that…" / "We all agree…" | Drop. Or attribute: "Most engineers I know…". |
| Aphoristic closers | "At the end of the day, it's about people." | Cut. End on the last real point. |
| Symmetrical pros/cons lists | Three pros, three cons, exact parallel length. | Asymmetric lists. Different sentence shapes per bullet. |

## Formatting tells

| Tell | Example | Rewrite pattern |
|------|---------|-----------------|
| Bolded key term every sentence | "We focus on **clarity**, **speed**, and **trust**." | Bold sparingly. At most one phrase per paragraph. |
| Em-dash-headed bullets | "— Fast setup\n— Easy config" | Use plain bullets, or numbered list. |
| Every bullet identical length | Robotic uniformity. | Vary length. Some bullets one word, some a full sentence. |
| Heading + 1-sentence section, repeated | Endless H3s with stubs underneath. | Combine sections, or drop the headings. |
| Emoji per bullet | "✅ Fast\n🚀 Scalable\n🔒 Secure" | Drop emoji unless the operator's voice already uses them. |
| "Here's the thing:" / "Here's why:" as setup | One-line setup for the next line. | Cut the setup, lead with the line. |

## Output protocol

Return two blocks, in this order:

1. **Rewrite.** The full revised text, ready to paste. No commentary inside it.
2. **Change log.** One bullet per tell category that fired. Format:
   - `<tell>: "<original snippet>" → "<replacement>"` (truncate snippets to ~80 chars).

If you cut a phrase entirely, write `→ (cut)`. If you merged sentences, write `→ (merged)`.

Keep the change log to the tells that actually fired. Do not list categories that didn't apply.

## Anti-overcorrection

- Do not change numbers, names, claims, code, commands, or quoted material.
- Do not introduce typos, slang, or fake informality. "Human" does not mean "sloppy".
- If the operator's voice is already present in the draft (recurring phrases, sentence shapes, idioms), preserve it. The goal is to remove AI tells, not to flatten the writer.
- Em-dashes are not banned. One per paragraph is fine when it's a real aside. The tell is using them as the default connective.
- Tricolons are not banned. The tell is reflexive tricolon for rhythm, not occasional use.
- Technical precision wins over flow. If a buzzword is actually the correct term in the field (e.g., "robust" in statistics, "leverage" in finance), leave it.
- If asked to humanize a very short text (one sentence, a headline), do the smallest change that removes the tell. Do not pad.
- If the draft is already clean, say so. Do not rewrite for the sake of rewriting.

## Invocation hint

Operator-friendly trigger phrases: "humanize this", "run humanizer on this", "de-AI this draft", "rewrite this in plain voice before I post it".
