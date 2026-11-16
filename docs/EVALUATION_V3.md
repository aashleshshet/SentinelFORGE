# V3 command semantics challenge: prespecified plan

This is a synthetic, engineer-authored contract experiment against baseline
`88bcda800bb877cd1e354301e7b727953157d962`. It is not representative operational
validation, an independently blinded holdout, or a calibrated probability of
compromise. A separate corpus-authoring agent received the public rule contracts
and evaluator interface, but inherited conversation context and knowledge of rule
families. No detector was executed during corpus authorship. No v2 holdout was
read or changed for this work.

## Allocation and meaning of labels

The allocation was specified before any v3 outcomes: 120 scenarios, partitioned
as 40 development, 40 validation and 40 holdout, each with 20 assigned suspicious
and 20 assigned benign actions. Every partition has:

| Allocation | Cases | Meaning |
| --- | ---: | --- |
| Observable assigned suspicious | 18 | Five PowerShell engine, three scheduled task, three UID-zero, three sudo-shell, four scoped PowerShell-file cases |
| Unobservable assigned suspicious | 2 | Malicious role/content is assigned in the label but absent from telemetry; unsupported ordinary commands must remain misses |
| Semantic/context near-match benign | 17 | Four engine boundaries, three task values, three UID values, three sudo executable identities, four context boundaries |
| Authorized but alertable benign | 3 | Legitimate administration meets the observable rule predicate without a modeled authorization exception |

`suspicious` and `reason` encode **assigned action intent**. They are not supplied
to ingestion or context APIs. `expected_rule_ids` separately encode the intended
command-semantic contract, including deliberately alertable legitimate actions.
The v3 expectations refine the old substring descriptions for task creation and
sudo shells; they are prespecified intended behavior, not a claim that the
baseline already implements those refinements. Inert encoded strings stand in
for programs; their content is not asserted to be malicious in isolation.

The deliberate ambiguity controls make perfect assigned-intent accuracy neither
expected nor an engineering objective. Under the stated contract, each split
retains three false positives and two false negatives (35/40 intent-correct,
87.5%) even with every contract fulfilled. Do not relabel or remove these cases,
or suppress legitimate signals by using case metadata, to inflate a headline.
No new operational accuracy or 100% efficacy claim is licensed by this corpus.

## Semantics and family boundaries

The five selected rule domains are PowerShell engine options, `schtasks` create,
`useradd` UID zero, sudo root-shell command identity, and scoped PowerShell file
observations. The cases challenge option-value consumption, arguments after
`-File` or `-Command`, genuine command verbs versus quoted data, exact numeric
UID meaning, executable identity versus an operand pathname, file-path/digest
binding and half-open intelligence windows. Plain commands with hidden assigned
intent and legitimate administrative operations remain in every split.

Narrow scenario families are assigned whole to one partition. Development uses
canonical encoded spellings and inline markers, local task creation, explicit
UID forms, direct sudo shells, simple Office file predicates and direct context
scope boundaries. Validation uses engine values before encoding, task run
identities, padded UID numbers, quoted/alternate sudo forms, abbreviated Office
options, and intelligence window boundaries. Holdout combines options and
identity observations, task action content, multiple UID options, shell argument
structure, Office combinations, and context binding/digest controls. This does
**not** make the splits independent: all reuse rule domains, constructors,
adapters, lexical primitives and engineer knowledge. Numbered hosts, sessions
and filenames distinguish records, not independent populations. Correlated
variants are disclosed rather than treated as 120 independent real incidents.

The current corpus concentrates on these five rules; SSH aggregation, reverse
shell and outbound-network rule coverage remains in existing regression suites
and historical experiments. No easy unrelated traffic was added as negatives.
Supported expressions are documented command strings, never executed by the
builder. These tests do not prove OS execution success or validate every native
shell/Windows quoting form.

The semantic basis is the official [PowerShell CLI documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_pwsh?view=powershell-7.5)
(engine parameters, aliases, consumed values and the File boundary),
[Windows PowerShell CLI documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1),
[Microsoft schtasks documentation](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-create)
(create syntax and task/action values), the upstream
[shadow-utils useradd manual](https://github.com/shadow-maint/shadow/blob/master/man/useradd.8.xml)
(UID and other option meanings), and the upstream
[sudo manual](https://github.com/sudo-project/sudo/blob/main/docs/sudo.man.in)
(command plus arguments as a different user). These were consulted on
2026-11-16. This corpus tests the documented subset and local detector contract;
it does not implement those full interpreters.

## Freeze and permitted evaluation order

`scripts/build_accuracy_corpus.py` constructs all three partitions without
importing detector, evaluator, API or adapter code. It asserts class counts,
ambiguity counts and disjoint IDs/sessions/narrow family identifiers. The first
run writes all partition JSON files and `data/evaluation-v3/manifest.json` with
exclusive creation; subsequent runs verify byte equality and refuse any
overwrite. The manifest records SHA-256 for each partition, the builder and this
plan, with the full baseline revision. `--check` can only verify. No post-outcome
editing of this plan or data is allowed; a correction requires a new version
while preserving these originals and reporting the reason.

1. Author and freeze every partition and this plan before running any v3 case.
2. Expose development data to implementation work. Treat the builder as sealed
   because it contains every partition definition.
3. Run the same frozen development data on the baseline and candidate; retain
   both result artifacts. Only development informs tuning initially.
4. Use validation for candidate selection. Record every evaluation and revision.
   Repeated validation use is selection evidence, never an untouched holdout.
5. Freeze candidate source, then run the holdout once. Report failures without
   tuning against them. Later reuse converts it into regression/development
   evidence and must be disclosed; do not silently regenerate the split.

The existing evaluator accepts these files with `--dataset`. Use its standard
run metadata (input hash, source hashes, dependency versions, fixed processing
clock and per-scenario errors). The clock is `2026-11-16T12:00:00Z`; event and
context windows are intentionally explicit. Synthetic script-path and digest
observations are adapter extensions, not claims that native Sysmon measures
script contents. Context is configured only using the authenticated operator
API format, with per-scenario binding/indicator provenance.

Report at least assigned-intent confusion counts, precision/recall/F1, rule
contract matches, false-positive and false-negative rationale, ingestion or
context errors, partition hash and candidate revision. Do not turn input errors
into correct negatives or omit them from denominators. Preserve original v2
artifacts and historical gate; do not replace their published results with v3.
Any apparent improvement is narrow synthetic evidence of these semantic fixes,
not a population-level estimate or replacement for real labeled telemetry.
