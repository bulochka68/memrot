# Source and license

`sample.json` is a curated subset (144 of 2071 `jailbreak==True` rows, after
exact-text de-duplication) of the
[TrustAIRLab/in-the-wild-jailbreak-prompts](https://huggingface.co/datasets/TrustAIRLab/in-the-wild-jailbreak-prompts)
dataset (both the `jailbreak_2023_05_07` and `jailbreak_2023_12_25` configs),
fetched via the Hugging Face `datasets-server` API 2026-09-06. The dataset is
MIT-licensed; this subset is redistributed under the same license.

Curation method: grouped by the dataset's own `source` column (12 distinct
communities/platforms -- ChatGPT, flowgpt, ChatGPTJailbreak, jailbreak_chat,
BreakGPT, etc.), sorted by prompt length descending within each group, kept
the top 13 per group (all of the one group with fewer). This spreads the
sample across every represented community rather than over-indexing on
whichever produced the most raw rows, consistent with this project's
"diversity over volume" preference. Prompts longer than 4000 characters are
truncated (`"truncated": true`) purely to keep the catalog file a practical
size; the truncation point is recorded, not hidden.

Used by `memrot.catalog.generator.ImportedBankGenerator`
(`bank="trustairlab_jailbreak"`) as `llm_jailbreak_susceptibility` threat-model
variants -- see `memrot/taxonomy.py` and `models.py`'s `threat_model`
field for why these are tagged separately from the memory-poisoning catalog.
