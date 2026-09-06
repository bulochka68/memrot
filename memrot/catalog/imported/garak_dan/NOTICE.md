# Source and license

The 14 `*.json` files in this directory are vendored verbatim from
[NVIDIA/garak](https://github.com/NVIDIA/garak), path `garak/data/dan/`,
fetched 2026-09-06. garak is licensed Apache-2.0; this copy is redistributed
under the same license. Each file is a JSON array of one or more full
DAN-family jailbreak prompt strings (DAN, AntiDAN, STAN, DUDE, ChatGPT
"Developer Mode" variants, etc.) used by `memrot.catalog.generator.ImportedBankGenerator`
(`bank="garak_dan"`) as the `llm_jailbreak_susceptibility` threat-model pool
-- see `memrot/taxonomy.py` and `models.py`'s `threat_model` field for
why these are tagged separately from the memory-poisoning catalog.
