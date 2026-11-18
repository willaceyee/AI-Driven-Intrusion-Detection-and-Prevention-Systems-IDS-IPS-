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

The repeated-row counts measure occurrences beyond the first copy of each row, comparing every column except `id`. There are also 940 distinct records shared between the training and testing files under that comparison, including the labels. These were preliminary overlap checks. Feature-only overlap and conflicting labels were inspected afterwards; see [Preprocessing inspection and proposed approach](#preprocessing-inspection-and-proposed-approach) and [Final baseline test evaluation](#final-baseline-test-evaluation).

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

Model selection used a grouped validation split created from the training file. The supplied test file was used for the final baseline evaluation and later for Priority 1 diagnostics, never for selecting models or thresholds. Duplicates and overlap are handled by grouped splitting and by reporting a test subset that excludes records also present in training.

## Preprocessing inspection and proposed approach

The step 4 inspection compared the 42 input features after excluding `id`, `label` and `attack_cat`. CSV headers were read using UTF-8 with BOM handling. Numeric values were compared as numbers and categorical values were stripped of surrounding whitespace.

All 39 numeric input columns could be parsed as finite, non-negative numbers in both files. This checks representation, rather than whether every value is valid for its documented meaning. In particular, `is_ftp_login` contains values 2 and 4 in training and 2 in testing. Their meaning requires confirmation before any conversion to a binary flag.

| Check | Training | Testing |
| --- | ---: | ---: |
| Distinct `proto` values | 133 | 131 |
| Distinct `service` values | 13 | 13 |
| Distinct `state` values | 9 | 7 |
| Records with `service` equal to `-` | 94,168 | 47,153 |
| Distinct input-feature records | 101,040 | 53,946 |
| Additional copies of input-feature records | 74,301 | 28,386 |
| Feature groups containing both binary labels | 229 | 6 |
| Feature groups containing multiple attack categories | 1,772 | 575 |

The test set contains two state values absent from training: `ACC` (4 records) and `CLO` (1 record). The encoder must support previously unseen categories. The service value `-` should remain an explicit category until its meaning is confirmed from the feature documentation.

There are 1,302 distinct input-feature records shared across the supplied partitions, covering 10,279 training rows and 8,541 testing rows. Of these shared groups, 279 contain both binary labels when the partitions are considered together. These counts differ from the earlier checks because labels are now excluded from the comparison. Conflicting labels mean that identical available inputs can have different recorded outcomes.

### Proposed preprocessing decisions for review

1. Preserve the raw CSVs and record transformations in a reproducible pipeline. Keep conflicting labels visible in the audit rather than automatically changing them.
2. Create an approximately 80/20 training/validation split from the supplied training file, using a fixed random seed of 42. Group identical input-feature records together, including those with conflicting labels, and aim to preserve binary class proportions. Report actual partition sizes and class counts because grouping can prevent an exact split.
3. Retain repeated observations for the initial benchmark, but report their frequency. Evaluate a deduplicated training variant separately if needed, with an explicit policy for conflicting labels.
4. Fit categorical encoding on the training portion only and handle unknown categories. Fit numeric scaling on that portion for Logistic Regression. Keep the same input definitions for all candidate models.
5. Select model settings and thresholds using validation data. Evaluate the final model on the official test set, reporting both full-set metrics and a separate subset excluding feature records present in the model's training data. Report subset sizes and class distributions, since exclusion changes the evaluation population.
6. Confirm the documented meaning of `is_ftp_login` and service placeholders before changing those values. Check feature ranges against their definitions before treating unusual numeric values as errors.

Decisions 1, 2, 4 and 5 were implemented in `preprocessing/prepare.py`, `models/train.py` and `evaluation/evaluate.py`. The deduplicated training variant in decision 3 was not evaluated, and the meaning of the `is_ftp_login` values in decision 6 remains unconfirmed.

## System design

This design describes the planned first version of the prototype. It establishes the interfaces that team members will use when implementing their components.

### Training and evaluation flow

The training workflow reads the prepared training CSV, validates its fields and creates the grouped training/validation split described above. Preprocessing and each candidate classifier are fitted on the training portion. Validation results guide model selection. The selected preprocessing and classifier are saved together with the required feature names and their order. The evaluation component then measures the selected system on the reserved test data, including the overlap-aware results already specified.

### Prediction flow

```text
CSV upload through dashboard
    -> Backend validates columns and values
    -> Saved pipeline transforms the 42 input features
    -> Trained classifier predicts normal or malicious
    -> Backend creates result records and simulated actions
    -> Dashboard displays results, alerts and simulated block entries
```

### Component responsibilities

| Folder | Responsibility | Output for other components |
| --- | --- | --- |
| `preprocessing/` | Define the input schema, validate data, create grouped splits and construct consistent preprocessing. | Shared validation logic and preprocessing used by training and prediction. |
| `models/` | Train candidate classifiers, compare validation results and save the selected pipeline. | Saved preprocessing/classifier pipeline and ordered feature names. |
| `backend/` | Receive uploaded CSVs, validate them, load the pipeline and construct predictions and simulated responses. | Structured per-record results and counts. |
| `frontend/` | Provide CSV upload, display validation messages, show prediction totals and list alerts and simulated block entries. | A user-facing demonstration of the complete workflow. |
| `evaluation/` | Calculate detection metrics, false positives, timing and overlap-aware test results. | Reproducible tables and figures for the report. |

### Input agreement

The upload must contain the 42 candidate feature columns identified in the dataset findings. Column order may vary in the file; the backend selects and orders features by their saved names. The three categorical fields are `proto`, `service` and `state`. The remaining 39 fields must contain finite numeric values. Domain-specific range rules will be confirmed against feature documentation during preprocessing implementation.

The supplied dataset CSV format is also accepted. Its optional `id`, `label` and `attack_cat` columns are excluded from prediction inputs. Additional unexpected columns, duplicate column names, missing required columns, empty files and malformed values produce a clear validation message. An invalid upload is rejected as a whole before predictions or simulated actions are created. Unknown categorical values are handled by the fitted encoder using the policy established during training.

### Backend and dashboard agreement

The backend returns one result per input row in the original order. The first data row has row number 1. Each upload receives a unique identifier, which is combined with the row number to form a demonstration record identifier. This identifier is independent of any dataset `id` value and is excluded from the model inputs.

| Result field | Meaning |
| --- | --- |
| `record_id` | Unique demonstration identifier for this upload and row. |
| `row_number` | Position of the data row in the uploaded CSV, starting at 1. |
| `predicted_label` | Integer `0` for normal or `1` for malicious. |
| `prediction` | Display text `normal` or `malicious`, consistent with the predicted label. |
| `simulated_action` | `allow` for normal or `block` for malicious. |

An illustrative result for a malicious prediction is shown below. It is an interface example, not an experimental result.

```json
{
  "record_id": "demo-upload-001-row-1",
  "row_number": 1,
  "predicted_label": 1,
  "prediction": "malicious",
  "simulated_action": "block"
}
```

The response also contains total record, normal prediction and malicious prediction counts. The dashboard presents malicious predictions as alerts and lists their demonstration identifiers in the simulated block list. These entries represent a simulated response for each record; they do not identify or block real network hosts. The first version displays the results and block list for the current upload, replacing the previous display after another successful upload.

### Integration checks

- A CSV with valid required features produces exactly one result per row, in the original order.
- Reordering input columns leaves predictions unchanged.
- Optional ground-truth columns are excluded from prediction, and changing them leaves predictions unchanged.
- Missing columns, duplicate headers and malformed numeric values produce readable validation errors before any simulated actions occur.
- An unseen category is processed according to the fitted encoder policy.
- A malicious prediction creates an alert and a simulated block entry with the same record identifier. A normal prediction receives an allow action.
- Summary counts equal the number of returned results, and the interface clearly labels simulated actions.
- A teammate can run the documented workflow using the saved pipeline and prepared demonstration data.

The next phase will select and document the shared Python environment and dependencies before implementation begins.

## Shared development environment

Use Python 3.12 for this project. The leader's existing environment uses Python 3.12.10. The initial stack uses pandas for data preparation, scikit-learn for preprocessing and models, joblib for saved pipelines, FastAPI and Uvicorn for the backend, Streamlit for the dashboard, requests for dashboard-to-backend communication, and Matplotlib for evaluation figures. The requirements file pins the installed packages and their dependencies for the tested Windows environment.

### New teammate setup on Windows

Open a terminal in the cloned repository folder, then run:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m pip check
```

In VS Code, run `Python: Select Interpreter` from the command palette and select the repository's `.venv/Scripts/python.exe`. Calling the environment's Python directly avoids needing to activate it in PowerShell.

The leader can continue using the existing environment in the parent folder. From the repository root, its Python executable is `../.venv/Scripts/python.exe`. Teammates should use their own environment rather than copying this folder.

Check the main imports with the following command. The leader should substitute the parent environment path when running it.

```powershell
.\.venv\Scripts\python.exe -c "import pandas, sklearn, joblib, fastapi, uvicorn, streamlit, requests, matplotlib; print('Environment imports passed')"
```

Download the two dataset files into `data/raw/` as described above. The existing ignore rules exclude virtual environments and raw data from commits. Installation on other operating systems requires separate verification because some pinned dependencies are platform-specific.

Application launch commands will be added when the backend and dashboard entry points are implemented.

## Running preprocessing

From the repository root, run the following using your selected Python environment:

```powershell
.\.venv\Scripts\python.exe preprocessing/prepare.py
```

For the leader's parent-folder environment, use `..\.venv\Scripts\python.exe preprocessing/prepare.py`.

The command validates the training CSV and takes the first fold of a five-fold stratified group split with seed 42. Complete feature tuples define the groups. It retains repeated observations and conflicting labels while keeping each identical feature group within one partition. The fitted transformer standardizes numeric features and one-hot encodes categorical features. Unknown categories produce all-zero indicators. Numeric parsing and finiteness are validated; domain-specific range restrictions remain pending feature-definition review. Values such as `service = -` and `is_ftp_login = 2` are preserved.

Generated files are stored locally in the Git-ignored `data/processed/` folder:

- `train.csv` and `validation.csv` retain the original columns for auditing. Model inputs must be selected through `validate_features`.
- `preprocessor.joblib` contains preprocessing fitted exclusively on the training partition.
- `split_report.json` records feature names, split counts and group checks.

The verified run produced 140,272 training rows (44,800 normal and 95,472 attack) and 35,069 validation rows (11,200 normal and 23,869 attack). There were zero shared feature groups between the partitions. The fitted transformer produced 193 columns. This run uses only the supplied training CSV. Re-running the command replaces the generated outputs.

The saved transformer is for the next model-training phase. Final model packaging must keep the fitted preprocessing and classifier together. If cross-validation is introduced later, preprocessing must be fitted separately inside each training fold.

## Training and comparing baseline models

From the repository root, run `python -m models.train` using the project environment. For the leader's existing environment, the command is:

```powershell
..\.venv\Scripts\python.exe -m models.train
```

This trains Logistic Regression (liblinear, maximum 2,000 iterations), an unrestricted Decision Tree and a Random Forest with 100 trees and two parallel workers. All use seed 42. These are initial baseline configurations. Each pipeline fits its own preprocessing exclusively on the prepared training partition and uses the same validation partition. Convergence warnings stop the run for investigation.

The selection criterion is highest attack-class validation F1, using lower false-positive rate to break ties. All models use their default prediction decision rules. This criterion is an initial project choice; deployment-specific false-alarm costs may justify a different threshold later, using validation data only.

The command writes `evaluation/validation_results.csv` and `evaluation/model_selection.json`, containing metrics, confusion counts, timing, model settings, source-file hashes and environment information. Prediction timing is the median of three warm batch runs including preprocessing, excluding file loading and input validation. It describes throughput on the current computer, rather than individual-request latency.

The selected preprocessing and classifier are saved together in `models/artifacts/selected_pipeline.joblib`, which is excluded from Git. The script verifies that reloading reproduces predictions on 100 validation records. Future backend code must validate uploaded features with `validate_features` before calling this pipeline. Only load trusted model artifacts.

The official test dataset was reserved for final evaluation. It has since been used once for the final baseline evaluation and, diagnostically, in the Priority 1 dataset-shift analysis; it was never used to select models or thresholds. Validation scores are used for model selection and should be labelled accordingly in the report. Re-running training replaces these reports and the selected artifact.

### Initial validation results

| Model | Precision | Recall | F1 | False-positive rate | Median batch prediction time |
| --- | ---: | ---: | ---: | ---: | ---: |
| Logistic Regression | 92.42% | 98.79% | 95.50% | 17.27% | 0.105 s |
| Decision Tree | 95.91% | 95.08% | 95.49% | 8.65% | 0.117 s |
| Random Forest | 95.86% | 97.41% | 96.63% | 8.96% | 0.456 s |

Each prediction timing covers all 35,069 validation records. Random Forest was selected by validation F1. It produced 1,004 false positives among 11,200 normal records and missed 618 of 23,869 attack records. Decision Tree had a slightly lower false-positive rate, while Random Forest recovered more attacks. The saved Random Forest remains fitted on the 140,272-row training partition. These are validation results; the official test evaluation is reported in [Final baseline test evaluation](#final-baseline-test-evaluation). Neither establishes performance on live traffic.

## Running the detection backend

From the repository root, use your project environment to start the local API:

```powershell
..\.venv\Scripts\python.exe -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Teammates whose environment is inside the repository should use `.\.venv\Scripts\python.exe`. The selected model artifact must already exist; run the Phase 8 training command first if needed. The backend loads the saved preprocessing and classifier once during startup.

Open `http://127.0.0.1:8000/docs` to try the API. Expand `POST /predict`, choose **Try it out**, select a UTF-8 CSV using the `file` upload field and click **Execute**. Use prepared validation data for the demonstration. `GET /health` reports readiness after model loading succeeds.

A successful prediction response contains an upload ID, `simulation: true`, total/normal/malicious counts, ordered per-record results and `simulated_block_list`. Each malicious result receives a block action and its demonstration identifier appears in that response's list. Each request has its own identifiers and list. The response represents the current upload and does not modify network controls.

Invalid uploads return HTTP 422 with a `detail` message. The API checks the whole input before prediction, including duplicate headers, incorrect row lengths, missing or unexpected columns, non-finite numbers and empty categories. Optional labels are excluded through the shared feature validator. Unknown categories use the fitted pipeline's existing handling. The current service is a local demonstration API; upload-size controls and concurrent-load performance have not been evaluated.

With the server running, verify the integration in a second terminal:

```powershell
..\.venv\Scripts\python.exe -m backend.check_api
```

The check compares 100 validation predictions with the saved model, checks result ordering and simulated actions, verifies label exclusion and reordered columns, exercises an unseen category and rejects ten invalid-upload cases. All checks passed during Phase 9 verification against a local server on port 8765. A different address can be supplied as the command's final argument.

For interactive testing in `/docs`, use `data/processed/demo_sample.csv` if available. It contains 100 validation records, with 50 from each recorded class, and is a demonstration sample rather than a representative evaluation set. Large CSV uploads return one result per row and can produce multi-megabyte JSON responses that are slow for the API documentation page to render. Swagger syntax highlighting is disabled to reduce rendering overhead. Restart the backend and reload `/docs` after changing this setting. Use the dashboard or a programmatic client for full-dataset results.

## Running the dashboard

Start the backend using the command above. In a second terminal at the repository root, run:

```powershell
..\.venv\Scripts\python.exe -m streamlit run frontend/app.py --server.address 127.0.0.1 --server.port 8501
```

Teammates with an environment inside the repository should substitute `.\.venv\Scripts\python.exe`. Open `http://127.0.0.1:8501`, upload `data/processed/demo_sample.csv` and click **Run detection**.

The dashboard uses a responsive dark Security Operations Center layout with seven persistent workspaces: Command Overview, Traffic Intelligence, Incident Investigation, Detection Intelligence, Prevention & Replay, Scenario Globe, and Model & Reports. The overview combines five evidence-backed KPI cards, the real prediction split, predictions across ordered CSV row segments, an investigation queue, simulated-prevention status, and entry points to the PCA and globe workspaces. Row sequence is file order rather than an event timeline. Investigation provides prediction, simulated-action and record search filters with previews limited to 100 rows. A selected traffic-intelligence or evaluation-audit record can be handed directly to investigation and replay. Attack replay steps through returned records in upload order and is explicitly a deterministic review rather than live packet playback. On narrow screens, the sidebar becomes a drawer and the overview cards and analytical panels stack without introducing a horizontally scrolling tab bar.

Traffic intelligence uses the actual uploaded feature records and their backend predictions. It applies the project's existing numeric scaling and categorical one-hot encoding, then fits a deterministic PCA projection to a class-aware sample capped at 1,200 records. Plotly supplies an interactive 3D view and a lower-cost 2D alternative. Position and distance represent similarity in transformed feature space only: they are not physical topology, communication edges, geography, devices, IP addresses, or event time. The interface reports the displayed components' explained variance and preserves the uploaded row number for record-level investigation.

The scenario globe is a separate deterministic tabletop aid. Its locations, paths, activity sequences and outcomes are explicitly synthetic and are never presented as Random Forest detections or global attack telemetry. It intentionally remains secondary to the real upload and investigation workflow.

Detection intelligence keeps historical validation and reserved-test evidence separate and adds a post-prediction audit when an uploaded CSV contains verified binary labels. Those optional labels and recorded attack categories are joined only after the backend returns predictions; the existing backend continues to exclude them from model inputs. The workspace provides confusion matrices, false-positive/false-negative inspection and error filters. Its disabled explanation and policy panels describe missing backend evidence without fabricating scores, thresholds or feature attribution. See `docs/NIDS-WEB-03A-api-contract.md` for the additive API proposal and leakage-safe Prevention Decision Lab methodology.

**Download all predictions (CSV)** includes every result and simulated action, while the JSON export preserves the complete backend response. The model-assurance view keeps validation evidence separate from the reserved test evaluation: validation attack F1 is 96.63% with 8.96% FPR, while reserved-test attack F1 is 89.43% with 26.77% FPR. The test figures were reproduced from the saved pipeline and local official test CSV; they are not metrics for the current upload and do not establish live-network effectiveness. Alerts and up to 100 simulated block-list entries remain visible in the investigation view. Changing the uploaded file clears the previous results, and each successful request replaces the current case. Counts describe predictions rather than measured accuracy; no live traffic, IP address, geolocation or attack category is inferred.

Streamlit and Plotly remain sufficient for this milestone because the current system is a local, reproducible upload-and-review workflow. They support the required session state, responsive layout, filtering, tables, bounded 3D interaction and accessible 2D fallback without adding a second frontend build. React should be reconsidered if a backend later provides genuine streaming events, communication edges or approved geolocation requiring high-frequency WebGL coordination across views.

The dashboard connects to the local backend on port 8000. It displays messages for unavailable services, invalid CSV uploads and request timeouts. A request waits up to 120 seconds for a response. Results are held in the current Streamlit session; large responses still require memory even though the visible tables are limited.

Streamlit AppTest verified the initial disabled button, a real 100-row API upload, metric rendering, result filtering and the preview limit. This test supplied the upload programmatically; manual browser file selection and download should also be checked during the team demonstration.

## Integration verification

On 7 November 2026, the local backend checks passed prediction parity on 100 records, row ordering, summary counts, simulated block actions, label exclusion, reordered columns, unseen categories and ten invalid-upload cases.

The dashboard integration check submits all 35,069 validation records through the running backend. It verifies both prediction filters, exact record handoff/search, the 100-row preview limit and equality between every exported CSV row and the response records. Runtime depends on the current computer and is a functional measurement rather than a browser load-test benchmark.

Invalid uploads were rejected through the live API. Simulated connection failures and timeouts displayed the expected messages and cleared previous results, preventing stale metrics from remaining visible. Dependency checks reported no broken requirements.

Run the repeatable checks with the backend active:

```powershell
..\.venv\Scripts\python.exe -m backend.check_api
..\.venv\Scripts\python.exe -m frontend.check_detection_intelligence
..\.venv\Scripts\python.exe -m frontend.check_traffic_intelligence
..\.venv\Scripts\python.exe -m frontend.check_dashboard
```

The traffic-intelligence check covers deterministic bounded sampling, PCA repeatability, filters, 2D fallback and synthetic-scenario stability. It and the frontend response-contract check do not require a running backend and are useful for quick UI regression checks:

```powershell
..\.venv\Scripts\python.exe -m frontend.check_dashboard_contract
```

The dashboard check uses Streamlit AppTest with programmatic uploads and captures the CSV supplied to the download button. Browser file selection, the browser's actual download operation, visual layout and installation on a different computer still require manual verification.

### Teammate verification checklist

1. Clone the repository, create a Python 3.12 environment and install `requirements.txt` using the shared-environment instructions.
2. Download the two UNSW-NB15 files into `data/raw/`.
3. Run `python preprocessing/prepare.py`, then `python -m models.train` with that environment. These steps recreate the ignored processed files and saved model required by the app.
4. Start `python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000`, then start the dashboard in another terminal with `python -m streamlit run frontend/app.py --server.address 127.0.0.1 --server.port 8501`.
5. Upload `data/processed/validation.csv` through the dashboard. The small `demo_sample.csv` is an optional local convenience file and is absent from a fresh clone.
6. Confirm predictions appear, try both filters, download the results and check that the CSV row count matches the dashboard total. Run both automated check commands above using the teammate's environment.
7. Record the teammate's name, operating system, Python version and outcome. This cross-computer verification remains pending until someone performs it.

## Final baseline test evaluation

Run `python -m evaluation.evaluate` from the repository root using the project environment. The evaluation loads the saved selected pipeline and applies its existing decision rule, without retraining or tuning on test data. It verifies the recorded training-file hash and records the model and test-file hashes.

| Metric | Full test set | Excluding records present in model training |
| --- | ---: | ---: |
| Records | 82,332 | 75,818 |
| Normal records | 37,000 | 35,821 |
| Attack records | 45,332 | 39,997 |
| Accuracy | 87.17% | 86.59% |
| Attack precision | 81.85% | 80.52% |
| Attack recall | 98.54% | 98.38% |
| Attack F1 | 89.43% | 88.56% |
| False-positive rate | 26.77% | 26.57% |
| False positives | 9,904 | 9,518 |
| Missed attacks | 661 | 646 |

The overlap check excludes 6,514 test rows whose 42 input values occur in the actual 140,272-row model-training partition. The earlier 8,541 count compared against the entire supplied training file, including the portion later used for validation. These comparisons answer different questions. The filtered test population has different class proportions and still may contain other relationships between records; removing exact overlap does not establish complete statistical independence.

Median prediction time was 1.071 seconds for all 82,332 records over three warm runs, including preprocessing and excluding CSV loading, validation, HTTP and dashboard rendering. This is batch timing on the leader's computer.

The Random Forest detected most attacks but incorrectly flagged more than one quarter of normal test records. Its validation F1 was 96.63%, compared with 89.43% on the full test set. This gap limits claims about generalisation. The similar false-positive rate after removing training overlap suggests exact overlap alone does not explain the false alarms. Priority 1 investigated their likely causes; see [Research Findings and Model Limitations](#research-findings-and-model-limitations).

Fuzzers accounted for 604 of the 661 missed attacks, with a detection rate of 90.04%. All 44 Worms records were detected, but that small sample provides limited evidence. The category report measures binary attack detection within each true category; the model does not predict individual attack types. For the Normal category, its attack-prediction rate is the false-positive rate.

The simulated prevention demonstration inherits these errors: a false-positive prediction would create an incorrect simulated block entry. These baseline results support reporting a functional prototype with substantial false-alarm limitations. Future experiments must document their development decisions and use a new untouched evaluation set for fresh confirmatory claims after these test results have informed development.

Outputs are `evaluation/test_results.csv`, `evaluation/test_category_results.csv`, `evaluation/test_evaluation.json` and `evaluation/test_confusion_matrices.png`. Metric totals and category totals were checked, F1 was independently recalculated from confusion counts, and the figure was visually inspected. The selected model artifact is unchanged by evaluation.

## Research Findings and Model Limitations

Priority 1 investigated the high official-test false-positive rate. The full report, with every figure and source file, is [docs/priority1_research_summary.md](docs/priority1_research_summary.md).

**Decision:** the original 42-feature Random Forest is retained, with the default classification threshold of 0.50. The research added analysis scripts, reports and documentation only. The saved model, preprocessing, backend and dashboard behaviour are unchanged.

| Official UNSW-NB15 test metric | Value |
| --- | ---: |
| Accuracy | 87.17% |
| Precision | 81.85% |
| Recall | 98.54% |
| F1-score | 89.43% |
| False-positive rate | 26.77% |

**What was investigated:**
- false-positive characteristics and traffic distributions
- prediction confidence and threshold sensitivity
- permutation feature importance
- grouped multi-seed robustness experiments with a random-seed noise control
- dataset-shift analysis across the training, validation and official test data

**Alternatives that were rejected:**
- **Threshold 0.60.** On the internal evaluation partition of the training data, it lowered FPR from 10.06% to 6.93% but missed 333 more attacks. Fuzzers recall fell from 85.83% to 76.16% and Analysis recall from 90.82% to 82.95%. It was not deployed and was never evaluated on the official test set. There, the deployed 0.50 model detects 90.04% of Fuzzers and 99.85% of Analysis records, so Analysis is weak only internally.
- **Removing `dttl`.** FPR was lower on only 1 of 5 seeds, and on average it rose by 0.14 percentage points. This did not pass the predefined multi-seed improvement criteria.
- **Removing all three TTL features (`sttl`, `dttl`, `ct_state_ttl`).** False positives on normal traffic with high TTL values fell on only 2 of 5 seeds, and on average rose slightly, within random-seed variation. This also did not pass the predefined criteria.

**Dataset shift:**
- The validation data is distributed like the training data: the largest KS statistic is 0.016. The official test data is not: its largest KS statistic is 0.27.
- Test normal records more often carry TTL values that mostly belong to attacks in training. For example, records with `sttl=254` are 20% of training normals but 41% of test normals, and they account for 8,886 of the 9,904 test false positives. Across two TTL-based grouping definitions and three reference weightings, about 53–79% of the FPR gap is associated with this TTL mix change ([`evaluation/report_stats/fpr_gap_decomposition.csv`](evaluation/report_stats/fpr_gap_decomposition.csv)). This is a descriptive sensitivity range, not a confidence interval, and it does not establish the causal contribution of TTL. The original decomposition figures are unchanged.
- These TTL-related changes are **associated** with the high test false-positive rate, but they have **not** been shown to be the sole cause:
  - removing the TTL features did not reduce false positives internally
  - normal traffic within the same TTL groups is also classified worse on the test set

Figures are in [`evaluation/shift_analysis/figures/`](evaluation/shift_analysis/figures/).

**Limitations:**
- **The high official-test FPR remains unresolved.** More than one in four normal test records is flagged as malicious, and simulated blocking inherits these errors.
- **Prevention is simulated.** The block list does not enforce real firewall rules or block network traffic.
- **The evaluation data has been reused.** The validation set and internal evaluation partitions were used repeatedly during development. The official test set was inspected for the baseline evaluation and the shift diagnostics. It was never used to select models or thresholds, but it is no longer untouched.
- **One dataset only.** All results come from UNSW-NB15, so generalisation to live or different networks is not established.
- **Scores are not calibrated probabilities.** Random Forest attack scores are vote fractions, not calibrated probabilities of an attack.
- **Confidence intervals are within-dataset only.** The 95% Wilson intervals in [`evaluation/report_stats/wilson_intervals.csv`](evaluation/report_stats/wilson_intervals.csv) assume independent records and ignore distribution shift. For example, the official-test FPR interval is 26.32–27.22%.

Reproduce the Priority 1 experiments from the repository root:

```powershell
python -m evaluation.experiment_multiseed
python -m evaluation.experiment_ttl_free_multiseed
python -m evaluation.analyze_dataset_shift
```

Report statistics and figures are rebuilt from the committed result files, without loading or training any model:

```powershell
python -m evaluation.report_statistics
python -m evaluation.report_figures
```
