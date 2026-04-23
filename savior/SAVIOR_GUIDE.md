# SAVIOR: Systematic Analysis of Vulnerabilities in Integrated OAuth Relying Parties

This repository contains the source code and accompanying artifacts for the paper *"The Tower of Babel: Systematically Analyzing Account Management Vulnerabilities in Web OAuth Integration"*.

## 1. Repository Contents

This repository includes:

- The core source code of SAVIOR's three-layer architecture
- The complete prompt templates for 7 tasks (i.e., the exact instructions given to the LLM)
- The invariant rule library (`configs/invariants.yaml`)
- Task entry scripts
- Two sanitized real-world example runs (Pinterest T6 and 2Captcha T2)

## 2. Architecture

SAVIOR implements the three-layer architecture described in Section 5.2 of the paper. Each layer has a single, clearly defined responsibility.
`semantic_navigator/tasks/` contains the task entry scripts that connect the three layers for each attack vector.

```text
+----------------------------------------------------------+
|  Semantic Navigator       semantic_navigator/            |
|  - Task entry points      tasks/t1_step1.py .. t7.py    |
|  - Prompt construction    task_orchestrator.py          |
|  - Iterative strategy     iterative_executor.py         |
|  - Prompt templates       prompts/t1_step1.txt .. t7.txt|
+----------------------------------------------------------+
|  Browser Interactor      browser_interactor/            |
|  - LLM invocation         claude_runner.py              |
|  - URL pre-filtering      url_prefilter.py              |
|  - CAPTCHA solving        captcha_solver.py             |
+----------------------------------------------------------+
|  State Auditor           state_auditor/                 |
|  - Invariant evaluation   invariants.py                 |
|  - Output parsing         verdict_parser.py             |
|  - Cross-check verdict    auditor.py                    |
|  - Report generation      evidence_compiler.py          |
+----------------------------------------------------------+
```

**Semantic Navigator** takes a task identifier and user-provided variables (URL, credentials, and task-specific parameters), and produces a fully instantiated prompt. This layer also defines the iterative execution strategy.

**Browser Interactor** takes that prompt and executes the audit through Claude Code + Playwright MCP, returning raw model output. When available, the output includes structured `<observations>`, `<verdict>`, and `<evidence>` blocks.

**State Auditor** takes the raw output, parses the structured blocks, evaluates YAML-defined invariants over the observations, reconciles the rule path and the LLM path, and produces the final report-ready artifacts.

### Algorithm 1 Function Mapping

Each function in Algorithm 1 of the paper maps to a concrete implementation:

| Algorithm 1 Function | Implementation |
| --- | --- |
| CONSTRUCTPROMPT | `semantic_navigator/task_orchestrator.py::construct_prompt()` |
| LLMORACLE | `browser_interactor/claude_runner.py::run_claude()` |
| PARSESTRUCTUREDOUTPUT | `state_auditor/verdict_parser.py::parse_output()` |
| EXTRACTVULNERABLEPATH | `state_auditor/auditor.py::extract_vulnerable_path()` |
| CAPTUREEVIDENCE | `state_auditor/auditor.py::capture_evidence()` |
| COMPILEREPORT | `state_auditor/evidence_compiler.py::compile_*_report()` |

## 3. Model and Configuration

All production audits use Claude Sonnet 4.5, invoked through the Claude Code CLI with default parameters (no temperature sweep and no custom sampling).

Browser automation is provided by the Playwright MCP server, which supports programmatic control of Chromium, including:

- Page navigation
- Element interaction
- Form filling
- Screenshot capture
- Cross-tab session management  
  for example, switching between the target website and Gmail to complete out-of-band email verification

SAVIOR separates semantic execution from invariant-driven verification:

- The **Browser Interactor** uses LLM-based semantic UI understanding to navigate and operate across heterogeneous web interfaces. For example, it can recognize that "unlink", "disconnect", and "remove account" correspond to the same authorization-revocation intent, and complete OAuth handshakes, email verification, and identifier collection without site-specific selectors or custom scripts.
- The **State Auditor** independently evaluates the collected observations against the formal security invariants defined in `invariants.yaml`, and reconciles the rule-path result with the Browser Interactor's verdict through a cross-check mechanism.

As a result, vulnerability decisions are grounded in both:

- semantic observations
- formal property verification

## 4. Detection Pipeline

For each attack vector Tk (k = 1..7):

### 1. Prompt Construction

`task_orchestrator.py` assembles the audit prompt from two sources:

- The task template `prompts/tk.txt`  
  which defines the browser-level testing steps
- The security invariants in `invariants.yaml`  
  which define the properties that the State Auditor will verify

The final prompt includes three parts:

- An invariant context block (`_build_auditor_context()`)  
  telling the LLM which security properties matter and what observations should be collected
- A step-by-step audit procedure  
  for example, opening the target URL, locating login or registration pages, performing OAuth flows, and collecting identifiers
- A structured output schema  
  defining the JSON fields inside `<observations>` for independent rule evaluation by the State Auditor

The complete prompts for all 7 vectors are included in `semantic_navigator/prompts/`.

### 2. Browser Execution

`claude_runner.py` invokes the Claude CLI via subprocess with:

- a default timeout of 600 seconds
- a default retry count of 2  
  retrying when Claude exits non-zero with empty output

The LLM performs the audit through Playwright and returns three structured blocks:

- `<observations>`  
  containing per-step booleans and collected identifiers
- `<verdict>`  
  containing STATUS / CONFIDENCE / REASONING
- `<evidence>`  
  containing vulnerability-analysis details

When CAPTCHA appears, the LLM invokes `2captcha.py` via subprocess.  
`captcha_solver.py` supports:

- reCAPTCHA v2/v3
- hCaptcha
- image CAPTCHAs

All CAPTCHA-solving events are logged.

### 3. Output Parsing

`verdict_parser.py::parse_output()` extracts structured blocks from the raw LLM output.

It implements a three-level fallback chain:

- **Level 1**  
  Parse XML-tagged blocks: `<observations>`, `<verdict>`, and `<evidence>`
- **Level 2**  
  If XML is absent, use task-specific regexes to extract legacy-format status values
- **Level 3**  
  If all parsing fails, return `None` while preserving the raw output for manual inspection

JSON parse errors are recorded in `observations_error` instead of being raised.

### 4. Dual-Path Verification

The system computes two independent verdict paths for the same run:

- **Rule path**  
  `invariants.py` recursively evaluates YAML-defined security invariants over `observations.task_specific`
- **LLM path**  
  uses the STATUS extracted from `<verdict>`

These two paths are deliberately independent:

- The rule engine does not see the LLM's natural-language reasoning
- The LLM does not know how the rule engine evaluates the result

### 5. Cross-check

`auditor.py::cross_check()` merges the two verdict paths into one of six outcomes:

- `verified`: both paths agree (high confidence)
- `uncertain`: the paths conflict (requires manual review)
- `rule_only` / `llm_only`: only one path produced a result
- `llm_only_na`: the LLM considers the task not applicable
- `unavailable`: neither path produced a result

### 6. Iterative Execution

`iterative_executor.py` implements the iterative execution strategy described in Section 6.2 of the paper. It typically runs each target 5-10 times to reduce variance from LLM-driven browser interaction.

The aggregation logic includes:

- **Early exit**: stop immediately once a non-`uncertain` `verified VULN` is found
- **Weak-signal handling**: e.g., `T5_WEAK` takes precedence over `SAFE`
- **Majority vote**: if no VULN is found, SAFE is aggregated by majority
- **Full history retention**: preserve per-iteration `status/source/confidence` for analysis

## 5. Invariants and Mapping to Table 1

Each invariant in `configs/invariants.yaml` encodes one vulnerability primitive Q from Table 1 of the paper as a mechanically evaluable condition. The `reference` field explicitly links each invariant to its corresponding Q number.

| Task | Primary Q | Invariant | Security property |
| --- | --- | --- | --- |
| T1_STEP1 | Q1 | INV_T1_1 | Registration without email verification |
| T1_STEP2 | Q4 | INV_T1_2 | OAuth automatically links to an unverified account |
| T2 | Q2, Q3 | INV_T2_1 | OAuth and email registration merge silently |
| T3 | Q5 | INV_T3_1 | Email change does not require old-email verification |
| T4 | Q7 | INV_T4_1 | Session persists after credential change |
| T5 | Q8 | INV_T5_1 | No OAuth binding management interface |
| T6 | Q6 | INV_T6_1 | Old IdP binding remains valid after identifier update |
| T7 | Q3 | INV_T7_1 | Premature identifier lock enables registration DoS |

The rule engine supports:

- `all_of`
- `any_of`
- `not`
- `leaf`

and the following comparison operators:

- `eq`
- `neq`
- `in`
- `not_in`
- `gt`
- `lt`

Missing observation fields are treated as `None` instead of causing exceptions.

Although T3 and T4 are tested in one script (`t3_t4.py`), they produce two independent verdicts.  
Accordingly, the invariant engine evaluates `verdict_rule_t3` and `verdict_rule_t4` separately.

### Design Note on T6

The paper describes T6 in relation to:

- Q6: Stale IdP Binding
- Q9: Incomplete Unbinding
- Q10: Hidden Binding Relationships

In the current implementation, Q6 is the main decision condition:  
if both OAuth identities can still access the same account after an identifier change, the old binding was not invalidated.

Q9 describes a related failure mode in which local records are removed but IdP-side tokens remain valid.  
Since a Q6 violation necessarily implies that the old binding still exists, Q6 detection already subsumes Q9 at the observation level.

Q10 (whether the binding relationship is visible to the user) is an independent property covered by T5.

## 6. Example Runs

`example_runs/` contains sanitized outputs from real-world cases corresponding to Section 6.7 of the paper.

### Pinterest T6: The Shadow Binding Attack (Section 6.7, Case B)

After the primary email was changed, the original Google OAuth binding remained valid.  
Both the old and the new OAuth identities could access the same account, indicating identity-state desynchronization (Q6).

Files:

- `pinterest_t6/pinterest_com.txt`
- `pinterest_t6/pinterest_com_report.txt`

### 2Captcha T2: Verification Context Confusion (Section 6.7, Case A)

Google OAuth registration bypassed the email verification required by normal registration, and silently linked both paths to the same account (Q2).

Files:

- `2captcha_t2/2captcha_com.txt`
- `2captcha_t2/2captcha_com_report.txt`

All test-account credentials have been sanitized.

## 7. Code Navigation

### Three key file types per attack vector

Each vector Tk corresponds to three key artifacts:

1. Audit procedure definition  
   `semantic_navigator/prompts/tk.txt`
2. Invariant definition  
   `configs/invariants.yaml`
3. Task entry point  
   `semantic_navigator/tasks/tk.py`

### State Auditor signal flow

`verdict_parser.py::parse_output()` extracts:

- `<observations>`
- `<verdict>`
- `<evidence>`

If structured output is missing, it falls back through the three-level parser chain.

### Cross-check logic

`auditor.py::cross_check()` compares the rule verdict and LLM verdict, producing:

- `verified`
- `uncertain`
- `rule_only`
- `llm_only`
- `llm_only_na`
- `unavailable`

### Iterative execution strategy

`iterative_executor.py` implements the multi-round execution logic described in Section 6.2.  
It supports:

- multi-round aggregation for standard tasks
- paired step1 + step2 execution for T1
- dual-verdict aggregation for T3_T4

## 8. Repository Layout

```text
savior/
  browser_interactor/              # Browser Interactor (Section 5.2.1)
    claude_runner.py               #   LLM invocation + retry/timeout
    url_prefilter.py               #   URL pre-filtering and deduplication
    captcha_solver.py              #   CAPTCHA integration
  semantic_navigator/              # Semantic Navigator (Section 5.2.2)
    task_orchestrator.py           #   Prompt construction + invariant injection
    iterative_executor.py          #   Iterative execution strategy (Section 6.2)
    prompts/                       #   Complete prompt templates for T1-T7
    tasks/                         #   Task entry points wiring all three layers
  state_auditor/                   # State Auditor (Section 5.2.3)
    invariants.py                  #   YAML rule engine
    verdict_parser.py              #   Structured output parsing + fallback
    auditor.py                     #   cross-check / evidence
    evidence_compiler.py           #   Report generation
  runner/                          # Batch experiment executor (Section 6)
    batch_runner.py
  utils/
    credentials.py                 #   Credential collection (via getpass)
    file_utils.py                  #   Directory management
  configs/
    invariants.yaml                # Q1-Q10 invariant library
  example_runs/
    pinterest_t6/                  # Pinterest T6 sanitized example
    2captcha_t2/                   # 2Captcha T2 sanitized example
  main_launcher.py                 # Single-task interactive entry
  oauth_test_runner.py             # Batch entry
  2captcha.py                      # Standalone CAPTCHA helper
```

## Security and Ethics

This tool is intended solely for responsible disclosure research under controlled conditions. All testing uses researcher-controlled accounts.  
Credentials are collected interactively via `getpass` and redacted in output reports.  
The CAPTCHA solver exists only to allow OAuth flows to proceed in automated testing.  
For usage boundaries and ethical assumptions, please refer to the paper's Ethics Considerations section.