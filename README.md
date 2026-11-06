## Project Scope

This project develops an AI-based intrusion detection prototype that analyses uploaded network traffic records, identifies potentially malicious activity, and demonstrates a simulated prevention response.

### Core Features

1. Upload network traffic records in a documented CSV format.
2. Preprocess records using the same pipeline used during model training.
3. Classify each record as normal or malicious.
4. Display predictions, alerts, and traffic summaries in a dashboard.
5. Demonstrate prevention by adding a simulated source identifier to a block list when malicious activity is detected. If the dataset contains no source identifiers, use clearly labelled demonstration identifiers.
6. Compare candidate models using precision, recall, F1 score, false-positive rate, and prediction time.

### Boundaries

The initial prototype uses dataset records rather than live network capture. The block list simulates a prevention decision; it does not change firewall settings or block real network traffic.

### Success Criteria

- A teammate can install and run the project using the README.
- Valid input records produce predictions displayed in the dashboard.
- A malicious prediction triggers an alert and a simulated block-list entry.
- Model evaluation uses held-out test data excluded from training and tuning.
- The complete workflow can be demonstrated repeatedly using prepared samples.

## Dataset findings

We selected UNSW-NB15 for the initial binary classification experiment. The local files are stored in `data/raw/`, which is excluded from Git. Each team member should download the same prepared training and testing files from the [official dataset page](https://research.unsw.edu.au/projects/unsw-nb15-dataset).

The following results come from an initial inspection of our downloaded CSV files.

| Check | `UNSW_NB15_training-set.csv` | `UNSW_NB15_testing-set.csv` |
| --- | ---: | ---: |
| Records | 175,341 | 82,332 |
| Columns | 45 | 45 |
| Normal records (`label = 0`) | 56,000 | 37,000 |
| Attack records (`label = 1`) | 119,341 | 45,332 |
| Empty or whitespace-only cells | 0 | 0 |
| Repeated rows after excluding `id` | 67,601 | 26,387 |

Both files have the same columns in the same order. They contain normal traffic and nine attack categories: Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode and Worms.

The repeated-row counts measure occurrences beyond the first copy of each row, comparing every column except `id`. There are also 940 distinct records shared between the training and testing files under that comparison, including the labels. These are preliminary overlap checks. Feature-only overlap and conflicting labels still need inspection before deciding how to handle duplicates during evaluation.

The absence of empty cells does not establish that all values are valid. Numeric validity, infinite values and categorical placeholders still need checking. The raw files should be preserved so that cleaning decisions can be reproduced.

## Prediction target and input features

The first experiment will classify each record as normal or malicious.

| Columns | Role |
| --- | --- |
| `label` | Prediction target: `0` represents normal traffic and `1` represents an attack. |
| `attack_cat` | Retained for analysis by attack category and excluded from model inputs because it reveals the target class. |
| `id` | Excluded from model inputs because it identifies the record. |
| Remaining 42 columns | Candidate input features, subject to preprocessing checks. |

The categorical input fields are `proto`, `service` and `state`. Their values must be inspected and encoded consistently during training and prediction. Any learned preprocessing will be fitted on the training portion only.

These prepared CSV files have no source-IP column. The simulated block list will therefore use clearly labelled demonstration identifiers, kept separate from the model inputs.

Model selection will use a validation split created from the training file. The supplied test file is reserved for final evaluation. A documented policy for duplicates and overlap is required before training and evaluation proceed.
