# r/LocalLLaMA

This sub cares about what runs locally and how. Lead with the technical details and the lessons, not the pitch. Say you're the developer. Check the sidebar for the self-promotion rule before posting.

**Title:**

```
Small local models kept making up my Mac's security score, so I stopped letting them guess (llama.cpp + MCP tools, open source)
```

**Body:**

I'm building Hashling, a free, MIT-licensed security agent for macOS. Its assistant can use Claude, but I wanted a mode where nothing leaves the Mac, so it can run a local model with llama.cpp. Some notes from getting that to behave:

**Setup is one switch.** Hashling installs llama.cpp with Homebrew, picks a GGUF by RAM and downloads it to `~/.hashling/models`, verifying the SHA-256 Hugging Face publishes. Stalled downloads resume from a `.part` file. `llama-server` (`--jinja`, 16k context) starts on the first question and stops after 10 idle minutes.

| Mac memory | Default |
|---|---|
| 8 to 16 GB | Qwen3 4B Instruct 2507 (Q4_K_M, 2.5 GB) |
| 24 to 32 GB | Qwen3 8B (Q4_K_M, 5 GB) |
| 36 to 48 GB | gpt-oss 20B (MXFP4, 12 GB) |
| 64 GB+ | Qwen3 30B-A3B (Q4_K_M, 19 GB) |

You can also pick any single-file GGUF from Hugging Face, a local `.gguf`, or point it at Ollama or LM Studio (loopback addresses only, so "local" stays true).

**What went wrong with small models, and what fixed it:**

1. *Qwen3 1.7B answered "is my Mac safe?" without calling a tool* and produced a confident score. Fix: Hashling calls its own `security_overview` first and puts a compact fact sheet (score, every open finding, blind spots) in the system prompt, labelled as the complete list.
2. *It described tools instead of calling them* ("call storage_report to see..."). Fix: a few regexes route common question types (space, what changed, uploads, AI apps) to a prefetch, so the data is there whether or not the model makes the call.
3. *It leaked tool names and invented "approve it below" lines* from the long Claude-oriented prompt. Fix: a separate short prompt for local models with five rules, and a focused set of 16 tools instead of 34.
4. *Tone.* 4B was alarmist ("remove it immediately"). One rule ("worth fixing is not an emergency") calmed it.

After that, Qwen3 4B gave grounded answers in 20 to 30 s on an M-series Mac with 16 GB, and handled scam checks well. The 1.7B still muddled details, so it's no longer an automatic pick; it's opt-in with a warning.

Tools come from Hashling's own MCP server over stdio, so the local model and Claude see exactly the same read-only tools. Anything that changes the Mac goes through `propose_action` and waits for Touch ID.

Code (the local AI part is `src/localai.ts`): https://github.com/0xArx/hashling
Site: https://gethashling.com

Curious what others do for tool-use grounding with sub-8B models. Prefetching beats hoping the model calls the tool, but I'd like something less hand-written than regexes.
