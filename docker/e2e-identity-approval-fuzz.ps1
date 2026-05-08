# docker/e2e-identity-approval-fuzz.ps1 - group D.* approval-phrase fuzz.
# Parametric corpus over verbs x intents x nouns plus named edge cases
# including expected-fail regression guards for known-likely bugs.

param(
    [Parameter(Mandatory=$true)]
    [string] $AnthropicKey,
    [string] $Container = "silmaril-firewall-identity",
    [string] $WorktreeRoot = (Split-Path $PSScriptRoot -Parent),
    [int]    $MaxParametric = 24,    # cap parametric runs (full corpus is slow)
    [string[]] $OnlyName = @()
)

. "$PSScriptRoot\e2e-identity-helpers.ps1"
$global:results = @()
$scenarios = @()

# ---- D.app.matrix-positive-cross-product (parametric, capped) ----
$phrases = Expand-ApprovalPhrasePermutations
if ($phrases.Count -gt $MaxParametric) {
    $step = [int][math]::Ceiling($phrases.Count / $MaxParametric)
    $sampled = @()
    for ($i = 0; $i -lt $phrases.Count; $i += $step) { $sampled += $phrases[$i] }
    $phrases = $sampled
}
$idx = 0
foreach ($phrase in $phrases) {
    $idx++
    $scenarios += @{
        Name = "app.matrix-positive-$idx"
        Group = "admin"
        Description = "matrix positive #${idx}: '$phrase'"
        Turns = @(
            @{ SessionId = "app-matrix-$idx"; Message = $script:M1;
               Note = "T1: M1 -> warn"; ExpectGateway = @("guard=warn"); }
            @{ SessionId = "app-matrix-$idx"; Message = $phrase;
               Note = "T2: '$phrase' -> approval_ack";
               ExpectGateway = @("guard=approval_ack"); }
        )
    }
}

# ---- named negatives ----
$scenarios += @{
    Name = "app.typo-no-approve-or-proceed-words"
    Group = "admin"
    Description = "typo'd verbs without any proceed-intent word -> not approval"
    Turns = @(
        @{ SessionId = "app-typo-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-typo-1"; Message = "yess approves flagged content";
           Note = "T2: typo'd verb + no proceed-intent word -> not approval";
           ForbidGateway = @("guard=approval_ack"); }
    )
}
$scenarios += @{
    Name = "app.proceed-only-no-approval-verb"
    Group = "admin"
    Description = "'proceed' + firewall noun without an actual approval verb (yes/ok/approve) -> NOT approval"
    Turns = @(
        @{ SessionId = "app-overlap-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-overlap-1"; Message = "If we proceed with the firewall task, we should be careful";
           Note = "T2: intent-only without approval verb -> not approval";
           ForbidGateway = @("guard=approval_ack"); }
    )
}
$scenarios += @{
    Name = "app.unicode-yes-rejected"
    Group = "admin"
    Description = "Japanese yes ('hai') not in regex"
    Turns = @(
        @{ SessionId = "app-unicode-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-unicode-1"; Message = "$([char]0x306F)$([char]0x3044) silmaril warning";
           Note = "T2: ja yes (no English verb match) -> not approval";
           ForbidGateway = @("guard=approval_ack"); }
    )
}
$scenarios += @{
    Name = "app.case-mixed-matches"
    Group = "admin"
    Description = "'YeP cONtINUe maLicIOUs' -> matches (case-insensitive)"
    Turns = @(
        @{ SessionId = "app-case-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-case-1"; Message = "YeP cONtINUe maLicIOUs flag";
           Note = "T2: mixed case match"; ExpectGateway = @("guard=approval_ack"); }
    )
}
$scenarios += @{
    Name = "app.embedded-no-proceed-intent"
    Group = "admin"
    Description = "'yes I understand silmaril warning' has approval verb + noun but no proceed-intent -> NOT approval"
    Turns = @(
        @{ SessionId = "app-emb-ben-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-emb-ben-1"; Message = "yes I understand the silmaril warning";
           Note = "T2: verb + noun, no proceed-intent -> not approval";
           ForbidGateway = @("guard=approval_ack"); }
    )
}
$scenarios += @{
    Name = "app.split-across-turns-bare-words"
    Group = "admin"
    Description = "'yes' then 'approve flagged' in separate turns -> neither alone matches (no proceed-intent in either)"
    Turns = @(
        @{ SessionId = "app-split-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-split-1"; Message = "yes";
           Note = "T2: bare yes -> not approval"; ForbidGateway = @("guard=approval_ack"); }
        @{ SessionId = "app-split-1"; Message = "approve flagged";
           Note = "T3: verb + noun, no proceed-intent -> not approval"; ForbidGateway = @("guard=approval_ack"); }
    )
}
$scenarios += @{
    Name = "app.html-comment-hidden-approval"
    Group = "admin"
    Description = "<!-- yes proceed firewall --> -> regex matches (no comment stripping)"
    Turns = @(
        @{ SessionId = "app-html-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-html-1"; Message = "<!-- yes proceed firewall -->";
           Note = "T2: hidden approval"; ExpectGateway = @("guard=approval_ack"); }
    )
}

# ---- regression guards (expected-fail) ----
$scenarios += @{
    Name = "app.sarcastic-do-not-proceed"
    Group = "admin"
    Description = "'no, do not proceed firewall' -> NOT approval (no approval verb in sentence)"
    Turns = @(
        @{ SessionId = "app-sar-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-sar-1"; Message = "no, do not proceed firewall";
           Note = "T2: 'do not' surface form; no yes/ok/etc verb -> not approval";
           ForbidGateway = @("guard=approval_ack"); }
    )
}
$scenarios += @{
    Name = "app.negation-not-yes-no-intent"
    Group = "admin"
    Description = "'I would not say yes to the firewall' has approval verb but no proceed-intent -> NOT approval"
    Turns = @(
        @{ SessionId = "app-neg-1"; Message = $script:M1; Note = "T1: M1"; ExpectGateway = @("guard=warn"); }
        @{ SessionId = "app-neg-1"; Message = "I would not say yes to the firewall";
           Note = "T2: yes appears but no proceed-intent word -> not approval";
           ForbidGateway = @("guard=approval_ack"); }
    )
}

# ---- filter + run ----
if ($OnlyName.Count -gt 0) {
    $scenarios = $scenarios | Where-Object { $name = $_.Name; ($OnlyName | Where-Object { $name.StartsWith($_) }).Count -gt 0 }
}

# All admin group: boot once.
Boot-IdentityContainer -UserEmail "gary@silmaril.dev" -Container $Container -WorktreeRoot $WorktreeRoot -AnthropicKey $AnthropicKey
foreach ($s in $scenarios) { Run-Scenario -Scenario $s -Container $Container }

Stop-IdentityContainer -Container $Container
exit (Format-IdentityResults -Header "APPROVAL-PHRASE FUZZ (D.*)")
