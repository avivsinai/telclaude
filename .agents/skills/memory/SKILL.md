---
name: memory
description: Social memory management for Telegram and social agents
allowed-tools:
  - Bash
---

# Memory Skill

You have access to a persistent memory system for storing facts about the user across conversations.

## When to Remember

- Explicit requests: "remember that...", "note that...", "my name is..."
- Biographical facts: name, location, profession, preferences
- Interests and hobbies mentioned across conversations
- Recurring topics or projects the user works on
- Working norms: how the user likes to collaborate, decide, review, ship, and communicate
- Shared history: things you and the user have already done together, recurring incidents, prior decisions, and context that would make you feel like a good long-term collaborator
- Post ideas the user wants to share on social services

Be proactive. If a fact is likely to help you be a better collaborator in a future conversation, save it.

## When NOT to Remember

- Transient requests or one-time questions
- Secrets, passwords, API keys, or tokens (these will be rejected automatically)
- Temporary context that won't matter next conversation
- Information the user asks you to forget

## Memory Categories

| Category | Use for | Examples |
|----------|---------|----------|
| `profile` | Biographical facts | Name, location, profession |
| `interests` | Hobbies, topics | "loves distributed systems", "plays guitar" |
| `meta` | General facts | Preferences, working style, timezone |
| `threads` | Conversation topics | Ongoing projects, recurring discussions |
| `posts` | Social post ideas | Ideas quarantined for user approval |

## CLI Commands

### Write a memory entry
```bash
telclaude memory write "<content>" --category <category> --chat-id <CHAT_ID>
```

### Read memory entries
```bash
telclaude memory read --categories profile,interests --chat-id <CHAT_ID>
```

### Quarantine a post idea for social posting (Telegram only)
```bash
telclaude memory quarantine "<post idea>" --chat-id <CHAT_ID>
```

The `--chat-id` flag scopes memory to the current conversation. Extract the chat ID from the `<chat-context chat-id="...">` tag in your system prompt.

## Auto-Injection

Profile, interests, meta, and shared-history context are automatically injected into the system prompt. You do NOT need to read them every turn — they are already available in your context.

Only use `memory read` when:
- The user asks "what do you know about me?"
- You need to check thread history for a specific topic
- You want to verify before overwriting an entry

## Memory Bias

Bias toward writing memory when the user reveals:

- life facts that are stable over time
- active workstreams or ongoing projects
- preferences about how they want you to help
- recurring collaborators, tools, or routines
- shared history that will make future conversations warmer or more effective

Prefer high-signal concise entries over long notes. One good memory entry beats five noisy ones.

## Elevation Flow (Telegram → Social)

When the user wants to share an idea on a social service:

1. Quarantine the idea:
   ```bash
   telclaude memory quarantine "Thought about distributed systems being like..." --chat-id <CHAT_ID>
   ```
2. Tell the user: "I've saved that as a post idea. To publish it, run `/promote <entry-id>`"
3. The user runs `/promote <id>` in Telegram to approve
4. On the next social heartbeat, the idea is posted

You CANNOT promote entries yourself — only the user can approve via `/promote`.

## Scope Awareness

### Telegram Agent
- Creates **trusted** entries by default
- Can read all Telegram memory for this chat
- Cannot read social memory
- Can quarantine post ideas for social posting

### Social Agent
- Creates **untrusted** entries by default
- Can only read social/untrusted entries
- Cannot read Telegram memory
- Cannot promote or quarantine entries (operator promotes via `/promote`)
- Post ideas (category `posts`) can be promoted by the operator for social posting
