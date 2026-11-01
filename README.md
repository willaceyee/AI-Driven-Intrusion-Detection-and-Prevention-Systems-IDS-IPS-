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