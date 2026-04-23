"""Task orchestration for the Semantic Navigator layer (§5.2.2).

Implements CONSTRUCTPROMPT from Algorithm 1: loads the prompt template,
injects auditor context from invariants, and substitutes variables.
"""

from pathlib import Path
from string import Template

from savior.browser_interactor.claude_runner import run_claude


def _prompt_path(task_id):
    """Map a task identifier to its prompt template path."""
    normalized = task_id.upper()
    mapping = {
        "T1_STEP1": "t1_step1.txt",
        "T1_STEP2": "t1_step2.txt",
        "T2": "t2.txt",
        "T3_T4": "t3_t4.txt",
        "T5": "t5.txt",
        "T6": "t6.txt",
        "T7": "t7.txt",
    }
    filename = mapping.get(normalized)
    if filename is None:
        raise NotImplementedError(f"Prompt template for {task_id} is not implemented yet")
    return Path(__file__).resolve().parent / "prompts" / filename


def _build_auditor_context(task_id):
    """Build the auditor context preamble from invariant descriptions.

    Corresponds to the context injection step of CONSTRUCTPROMPT (Alg. 1 line 1).
    The preamble tells the LLM which security properties the auditor cares about,
    so it can ensure its observations cover the relevant facts.
    """
    try:
        from savior.state_auditor.invariants import get_task_config
        config = get_task_config(task_id)
    except (NotImplementedError, KeyError):
        return ""

    invariants = config.get("invariants", [])
    if not invariants:
        return ""

    lines = [
        "[Auditor Context -- for your awareness while performing this task]",
        "The following security properties are being verified:",
    ]
    for inv in invariants:
        ref = inv.get("reference", "")
        desc = inv.get("description", "").strip().replace("\n", " ")
        lines.append(f"- {inv['id']} ({ref}): {desc}")
    lines.append("Please ensure your observations cover the facts needed to evaluate these properties.")
    return "\n".join(lines)


def construct_prompt(task_id, variables):
    """Load and substitute the prompt template for a single task execution.

    Implements CONSTRUCTPROMPT (Alg. 1 line 1): loads the template file,
    injects auditor context from invariants.yaml, and substitutes all
    $variable placeholders via string.Template.safe_substitute().
    """
    prompt_path = _prompt_path(task_id)
    text = prompt_path.read_text(encoding="utf-8")

    # Inject auditor context if not already provided by caller
    if "auditor_context" not in variables:
        variables = dict(variables)  # don't mutate caller's dict
        variables["auditor_context"] = _build_auditor_context(task_id)

    prompt = Template(text).safe_substitute(variables)

    # Warn about unresolved $placeholders (safe_substitute leaves them intact)
    import re as _re
    unresolved = _re.findall(r"\$([a-zA-Z_]\w*)", prompt)
    # Filter out variables that were actually provided
    unresolved = [f"${name}" for name in unresolved if name not in variables]
    if unresolved:
        import warnings
        warnings.warn(f"Unresolved prompt placeholders: {', '.join(sorted(set(unresolved))[:5])}")

    return prompt


def execute_task(task_id, variables, timeout_seconds=600, max_retries=2):
    """Construct a prompt, run Claude, and return both prompt and raw output."""
    prompt = construct_prompt(task_id, variables)
    result = run_claude(prompt, timeout_seconds=timeout_seconds, max_retries=max_retries)
    result["prompt"] = prompt
    return result
