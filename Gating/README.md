# Phoenix Security Posture Gating

This directory contains scripts for interacting with Phoenix Security's posture gating APIs.

## Scripts

### 1. Phoenix Posture Gating Script (`phoenix_posture_gating.py`)
Query vulnerability posture data for applications and components.

### 2. Policy Gating Script (`policy_gating.py`)
Evaluate vulnerability counts against defined thresholds and determine if they pass or fail the policy gate.

## Policy Gating Features

- Define vulnerability thresholds in a JSON policy file
- Specify which gates are mandatory ("must") vs. optional
- Choose between different pass logic modes (ALL or REQUIRED)
- Detailed failure reporting with color-coded output
- Visual indicators for threshold comparisons (+/- values)
- Support for real Phoenix API response formats

### Policy Configuration

Create a `policy.json` file with your desired thresholds and requirements:

```json
{
    "gates": [
        {
            "severity": "critical",
            "threshold": 3,
            "required": "must"
        },
        {
            "severity": "high",
            "threshold": 18,
            "required": "optional"
        },
        {
            "severity": "medium",
            "threshold": 12,
            "required": "optional"
        },
        {
            "severity": "low",
            "threshold": 0,
            "required": "optional"
        },
        {
            "severity": "none",
            "threshold": 0,
            "required": "optional"
        }
    ],
    "pass_logic": "ALL"
}
```

#### Policy Options

- **Pass Logic**:
  - `ALL`: All gates must pass for overall pass
  - `REQUIRED`: Only required ("must") gates need to pass

- **Gate Requirements**:
  - `must`: Gate must pass for overall pass (when using REQUIRED logic)
  - `optional`: Gate can fail without failing overall pass (when using REQUIRED logic)

### Usage

1. Run the policy gating script:
```bash
python3 policy_gating.py
```

2. Choose evaluation type:
   - Option 1: Application evaluation
   - Option 2: Component evaluation

3. Enter required information when prompted

4. View results:
   - Overall gate status (PASSED/FAILED)
   - Detailed evaluation for each severity level
   - Color-coded comparison indicators:
     - `=` (yellow): Exactly at threshold
     - `-N` (green): N under threshold
     - `+N` (red): N over threshold
   - Summary statistics and decision explanation

### Testing the Gate

You can test the policy gate with sample data:

```bash
python3 test_policy_gate.py
```

This will run several test scenarios including:
- Applications under threshold (should pass)
- Applications over threshold (should fail)
- Components with multiple violations
- A simulated Phoenix API response

### Alternative Policy Files

The repository includes multiple policy files for testing:

- `policy.json`: Default policy where ALL gates must pass
- `policy_required_only.json`: Only required gates must pass

To test with a different policy:

```python
gate = PolicyGate("policy_required_only.json")
```

## Phoenix Posture Gating Script

The `