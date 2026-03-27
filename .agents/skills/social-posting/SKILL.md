---
name: social-posting
description: Guides the social agent on crafting posts and threads for X/Twitter. Use when creating proactive posts, threads, or engaging with timeline content. Covers thread structure, hook techniques, formatting, and structured output format.
---

# Social Posting Skill

You are telclaude's public persona posting to X (Twitter). This skill teaches you how to craft compelling single posts and threaded conversations.

## When to Thread vs. Single Post

| Signal | Format |
|--------|--------|
| One clear thought, take, or reaction | Single post (≤280 chars) |
| Idea needs explanation, evidence, or steps | Thread (5-7 tweets) |
| Listicle (N tools, lessons, tips) | Thread (1 item per tweet) |
| Story with arc (struggle → insight → outcome) | Thread |
| Quick engagement (reply, quote-tweet energy) | Single post |

**Default to single post.** Only thread when the idea genuinely needs room to breathe.

## Single Post Rules

- Hard limit: 280 characters. Aim for under 250 to leave room for retweet comments.
- One idea per post. If you need a second idea, it's a thread.
- Line breaks improve scannability. Two short lines beat one long sentence.
- No hashtags in the body. Save 1-2 for visibility at the end, only if natural.
- Emojis: one max, for emphasis. Zero is fine. Never decorative.
- URLs count as 23 characters regardless of length (t.co shortening).

## Thread Architecture

Every thread has five parts:

### 1. Hook (Tweet 1) — The Most Important Tweet

This tweet appears in the timeline. It determines whether anyone clicks "Show this thread." Keep it under 180 characters. End with a colon, ellipsis, or arrow to pull readers in.

**Six hook patterns:**

| Pattern | Template |
|---------|----------|
| Bold declarative | "[Bold claim]. Here's [what/how]:" |
| Thought-provoking question | "[Question with surprising answer]?" |
| Contrarian take | "[Opinion most think but don't say]." |
| Moment in time | "[Specific past event]. [Surprising outcome]." |
| Vulnerable confession | "I [painful admission]. Here's what I learned:" |
| Insider secrets | "[System] has [hidden features]. Here are [N]:" |

**Hook rules:**
- Use specific numbers ("7 lessons", "3 years", "$50K"), not vague quantities
- Never start with "Thread:" or "A thread about..." — kills curiosity
- Write 3-5 hook variants mentally, pick the most specific and curiosity-inducing one
- The hook must create a gap between what the reader knows and what they want to know

### 2. Context (Tweet 2, optional)

Expands on the hook with your strongest insight or credibility signal. Delivers the "why should I keep reading" answer. Skip if the hook is self-sufficient.

### 3. Body (Tweets 3 through N-2)

The value payload. Rules:
- **One idea per tweet.** If listing "7 lessons," one tweet per lesson.
- **Each tweet stands alone.** Someone seeing only tweet 5 (via quote-retweet) should still find it useful.
- **Open loops.** End 70%+ of body tweets with a pull-forward: "Here's where it gets interesting:" / "But that's only half the story." / "This next one surprised me most."
- **Vary format.** Alternate between: statement + explanation, numbered step + example, question that reframes, data point, one-line punchy insight.
- **Target under 200 characters per tweet.** Under 250 acceptable. Never fill all 280.
- **Line breaks within tweets.** Two short lines are more scannable than one paragraph.

### 4. Bridge/Summary (Tweet N-1)

Recap the key takeaway in a shareable, quotable format. This tweet often gets quote-retweeted independently — make it self-contained and memorable. A good bridge answers: "If someone reads only this tweet, do they get the core insight?"

### 5. CTA (Final Tweet)

A direct, specific ask. Rules:
- Limit to 1-2 asks. More dilutes action.
- The CTA must feel earned — only ask after delivering value.
- Frame as benefit to reader: "Get the full breakdown" not "Please subscribe."
- Best CTAs for reach: engagement asks ("Which resonated most? Reply below.") — replies carry significantly more algorithmic weight than likes.
- Place 1-2 hashtags here if relevant. Nowhere else in the thread.

## Thread Length

| Length | Use Case |
|--------|----------|
| 3-4 tweets | Too short for most threads. Feels incomplete. |
| **5-7 tweets** | **Default target.** Enough depth without losing readers. |
| 8-12 tweets | Detailed tutorials, case studies, resource lists. Requires strong pacing. |
| 13+ tweets | Almost always too long. Split into multiple threads. |

## Formatting Rules

- **No "Thread:" prefix.** No thread emoji in the hook.
- **Number body tweets** with "1/", "2/", etc. if listing items. Omit numbering for narrative/story threads.
- **No hashtags in body tweets.** Save for CTA only.
- **No tagging** other accounts in body unless directly relevant.
- **Line breaks are free.** Use them.

```
BAD (wall of text):
"The most important thing about writing threads is that you need to focus on the hook first because most threads fail to capture attention and the algorithm prioritizes early engagement."

GOOD (scannable):
"Most threads fail.

Not because the content is bad.

Because the hook doesn't stop the scroll."
```

## What Makes Threads Succeed

**Do:**
- Specific numbers and named examples over abstract advice
- First-person voice ("I learned" not "one learns")
- Personal stories with lessons — highest engagement pattern
- High-arousal emotions: awe, excitement, surprise
- Engage with replies in the first hour after posting

**Don't:**
- Generic hooks ("Here's a thread about productivity")
- Dense text walls
- External links in multiple tweets (algorithm suppresses)
- Wandering from the central thesis
- Excessive emojis or hashtags
- Posting for the sake of posting

## Thread Templates

### Template A: Lessons Learned
```
Hook: "I [did X]. Here are N lessons:"
Tweet 2-N-1: One lesson per tweet (most surprising first)
Bridge: "TL;DR: [key takeaway]"
CTA: "If this helped, [ask]. Follow for more."
```

### Template B: Step-by-Step
```
Hook: "[Outcome promise]. Here's the exact [N]-step process:"
Tweets: One step per tweet with specific action
Penultimate: "Common mistakes to avoid: [brief list]"
CTA
```

### Template C: Contrarian Take
```
Hook: "[Common advice] is wrong. Here's why:"
Tweet 2: Why common advice fails (with data/example)
Tweets 3-5: The alternative approach with evidence
Tweet 6: Results/proof
CTA
```

### Template D: Story Arc
```
Hook: "[Specific moment]. [Surprising outcome tease]."
Tweet 2: The low point / starting situation
Tweets 3-4: Turning point + what changed
Tweets 5-6: The climb / specific actions
Tweet 7: Result + key insight
CTA
```

### Template E: Curated List
```
Hook: "N [tools/resources] that [specific benefit]:"
Tweets: One resource per tweet (name + what it does + why it matters)
CTA: "Save this thread for later"
```

## Output Format

When you decide to create a thread, output your response as structured JSON:

```json
{
  "action": "thread",
  "tweets": [
    "First tweet (the hook) — under 180 chars",
    "Second tweet — the context or first body point",
    "Third tweet — body continues",
    "Fourth tweet — body continues",
    "Fifth tweet — bridge/summary, quotable",
    "Final tweet — CTA with optional hashtags"
  ]
}
```

When creating a single post, use the existing format:

```json
{
  "action": "post",
  "content": "Your single tweet text here"
}
```

When skipping:

```json
{
  "action": "skip",
  "reason": "Brief explanation"
}
```

## Pre-Flight Checklist

Before outputting a thread, verify:

1. Does tweet 1 create a curiosity gap? Is it under 180 chars?
2. Does the thread deliver on the hook's promise?
3. One idea per tweet?
4. Do 70%+ of body tweets have open loops?
5. Would each body tweet make sense if seen alone?
6. Each tweet under 200 chars (250 max)?
7. Total length 5-7 tweets (8-12 only if content demands it)?
8. CTA present in final tweet?
9. No links in hook? URLs only in final tweet?
10. No hashtags in body? 1-2 max in CTA?
11. First-person voice?
12. Zero typos?
