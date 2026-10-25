# Usage report

Final full-dataset run that produced `output.csv` (`python3 code/main.py`, 518 requests).

| Item | Value |
| --- | --- |
| Model providers | none in the final run (optional VLM layer disabled: no API key) |
| Model names | none (local OCR ensemble + deterministic rules) |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0.0 |
| Estimated total cost | USD 0.00 (list price assumed $3/M input, $15/M output) |
| Estimated cost per request | USD 0.0000 |
| Per-model totals | not applicable |
| Wall-clock for a clean run | about 45 seconds on one CPU core (multi-pass OCR) |

The submitted run used no external API, key or network access. The optional vision-model layer (`ANTHROPIC_API_KEY`) was not enabled, so nothing was billed; if enabled, its calls and tokens are recorded here automatically.
The coding assistant used to *develop* the agent is logged separately in `log.txt`.
