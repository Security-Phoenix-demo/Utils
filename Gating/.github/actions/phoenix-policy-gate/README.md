# Phoenix Security Policy Gate GitHub Action

This GitHub Action checks your application and components against Phoenix Security vulnerability data and enforces policy gates. The action will run policy checks for all entities defined in your core-structure file and fail if any required gates don't pass.

## Configuration

### Secrets Required

- `PHOENIX_CLIENT_ID`: Your Phoenix API client ID
- `PHOENIX_CLIENT_SECRET`: Your Phoenix API client secret
- `PHOENIX_API_URL` (optional): Phoenix API URL (defaults to https://api.poc1.appsecphx.io)

### Setup

1. Create a `Phoenix-Security` directory in your repository
2. Create one of the following core-structure files:

   **Simple Format** (core-structure)
   ```
   application: your-app-name
   component: your-component-name
   ```
   
   **YAML Format** (core-structure.yaml or core-structure.yml)
   ```yaml
   DeploymentGroups:
   - AppName: SPHX_Deployment_AUTO
     Components:
     - ComponentName: SPHX_Frontend_Auto
     - ComponentName: SPHX_Backend_Auto
   ```

   The action will check both the application and all components listed in the file.

3. Create a `policy.json` file to specify your policy gates:
   ```json
   {
     "gates": [
       {"severity": "critical", "threshold": 3, "required": "must"},
       {"severity": "high", "threshold": 18, "required": "optional"},
       {"severity": "medium", "threshold": 12, "required": "optional"},
       {"severity": "low", "threshold": 0, "required": "optional"},
       {"severity": "none", "threshold": 0, "required": "optional"}
     ],
     "pass_logic": "REQUIRED"
   }
   ```

## Pass Logic Options

- `REQUIRED`: Only gates marked as "must" will affect the overall pass/fail status
- `ALL`: All gates must pass for the overall check to pass

## Multi-Entity Behavior

The action will:
1. Run a policy gate check for the application itself
2. Run a policy gate check for each component listed in the core-structure
3. Provide individual results for each entity
4. Fail the overall workflow if ANY of the entities fail their required gates

## Example Workflow

Add this to your GitHub workflow file:

```yaml
name: Phoenix Security Check

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
          
      - name: Install dependencies
        run: pip install requests termcolor colorama pyyaml
        
      - name: Run Phoenix Policy Gate
        run: python .github/actions/phoenix-policy-gate/phoenix_policy_gate_action.py
        env:
          PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
          PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
```

## Manual Overrides

You can override the application or component name by setting environment variables:

```yaml
- name: Run Phoenix Policy Gate
  run: python .github/actions/phoenix-policy-gate/phoenix_policy_gate_action.py
  env:
    PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
    PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
    APPLICATION_OVERRIDE: "different-app-name"
    COMPONENT_OVERRIDE: "different-component"
```

When using overrides, only the specified application and/or component will be checked, instead of all entities in the core-structure file.

## Outputs

The action produces:
- Console output with colored results for each entity
- Overall summary showing all entities and their status
- GitHub step summary with Markdown formatted results (both overall and detailed for each entity)
- GitHub output variables:
  - `gate_passed`: true/false (overall status across all entities)
  - `gate_results`: JSON string with summary of all entity results
  - `individual_results`: JSON array containing detailed results for each entity 