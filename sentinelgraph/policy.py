"""Deterministic implementation of the supplied Fraud Policy v1.0.

The LLM may propose hypotheses and write explanations. It must not override this
module's exact action names, approval routes, or mandatory policy constraints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Action(StrEnum):
    ALLOW_TRANSACTION = "ALLOW_TRANSACTION"
    DECLINE_TRANSACTION = "DECLINE_TRANSACTION"
    MONITOR_CARD = "MONITOR_CARD"
    MONITOR_CONNECTED_CARDS = "MONITOR_CONNECTED_CARDS"
    WARN_CUSTOMER = "WARN_CUSTOMER"
    VERIFY_WITH_CUSTOMER = "VERIFY_WITH_CUSTOMER"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    BLOCK_CARD = "BLOCK_CARD"
    BLOCK_ALL_CARDS = "BLOCK_ALL_CARDS"
    GENERATE_REPORT = "GENERATE_REPORT"
    CREATE_CASE = "CREATE_CASE"
    FILE_REPORT = "FILE_REPORT"
    ESCALATE_TO_ANALYST = "ESCALATE_TO_ANALYST"
    CLOSE_NO_FRAUD = "CLOSE_NO_FRAUD"


class ApprovalRoute(StrEnum):
    AUTO = "auto"
    L1 = "L1"
    L2 = "L2"


class CustomerResponse(StrEnum):
    DENIED = "denied"
    CONFIRMED = "confirmed"
    NO_REPLY_24H = "no_reply_24h"


@dataclass(frozen=True)
class CaseFacts:
    """Verified facts supplied by graph tools and evidence adapters only."""

    fraud_probability: float
    exposure_usd: float
    trigger_type: str
    evidence_families: int
    verdict: str = "uncertain"
    customer_response: CustomerResponse | None = None
    card_testing: bool = False
    large_testing_purchase_cleared: bool = False
    shared_origin: bool = False
    connected_fraud: bool = False
    recurring_legitimate_pattern: bool = False
    conflicting_evidence: bool = False
    undocumented_coordinated_abuse: bool = False
    confirmed_fraud_on_two_customer_cards: bool = False
    credentials_confirmed_compromised: bool = False
    pending_authorization: bool = False

    def __post_init__(self) -> None:
        if not 0 <= self.fraud_probability <= 1:
            raise ValueError("fraud_probability must be in [0, 1]")
        if self.exposure_usd < 0:
            raise ValueError("exposure_usd cannot be negative")
        if self.evidence_families < 0:
            raise ValueError("evidence_families cannot be negative")


@dataclass(frozen=True)
class RecommendedAction:
    action: Action
    route: ApprovalRoute
    reason: str


@dataclass(frozen=True)
class PolicyDecision:
    actions: tuple[RecommendedAction, ...]
    should_open_case: bool
    should_file_sar: bool
    should_request_evidence: bool
    can_stop: bool
    stop_reason: str | None
    warnings: tuple[str, ...] = field(default_factory=tuple)


AUTO_ACTIONS = {
    Action.ALLOW_TRANSACTION,
    Action.MONITOR_CARD,
    Action.MONITOR_CONNECTED_CARDS,
    Action.WARN_CUSTOMER,
    Action.VERIFY_WITH_CUSTOMER,
    Action.STEP_UP_AUTH,
    Action.GENERATE_REPORT,
    Action.CREATE_CASE,
    Action.ESCALATE_TO_ANALYST,
    Action.CLOSE_NO_FRAUD,
}


def approval_route(action: Action, exposure_usd: float) -> ApprovalRoute:
    if action in AUTO_ACTIONS:
        return ApprovalRoute.AUTO
    if action is Action.DECLINE_TRANSACTION:
        return ApprovalRoute.L1
    if action is Action.BLOCK_CARD:
        return ApprovalRoute.L1 if exposure_usd <= 2500 else ApprovalRoute.L2
    if action in {Action.BLOCK_ALL_CARDS, Action.FILE_REPORT}:
        return ApprovalRoute.L2
    raise ValueError(f"No approval route configured for {action}")


def _add(actions: list[RecommendedAction], action: Action, exposure: float, reason: str) -> None:
    if any(item.action is action for item in actions):
        return
    actions.append(RecommendedAction(action, approval_route(action, exposure), reason))


def _must_file_sar(facts: CaseFacts) -> bool:
    """Policy 3a/R2/R6/R9: a report requires suspected/confirmed fraud plus trigger."""
    strong_suspicion = facts.verdict == "fraud" or facts.fraud_probability >= 0.85
    if not strong_suspicion:
        return False
    return (
        facts.exposure_usd > 1000
        or facts.shared_origin
        or facts.connected_fraud
        or facts.undocumented_coordinated_abuse
    )


def evaluate_policy(facts: CaseFacts) -> PolicyDecision:
    """Compile policy-compliant actions from verified case facts.

    Ordering matters: immediate containment comes first, then case/reporting and
    monitoring. The caller is responsible for producing initial/final decisions
    with facts from before/after simulated evidence respectively.
    """

    actions: list[RecommendedAction] = []
    warnings: list[str] = []
    should_open_case = facts.fraud_probability >= 0.30 or facts.trigger_type == "customer_report"
    request_evidence = False

    # A customer dispute always opens an internal case (policy 3a).  Before the
    # controlled validation result returns, preserve the alert and request the
    # authorization evidence rather than silently leaving the initial action set
    # empty merely because several graph signals already exist.
    if facts.trigger_type == "customer_report" and facts.customer_response is None:
        _add(
            actions,
            Action.CREATE_CASE,
            facts.exposure_usd,
            "Policy 3a: customer dispute requires an internal case",
        )
        _add(
            actions,
            Action.VERIFY_WITH_CUSTOMER,
            facts.exposure_usd,
            "R1/Policy 3a: obtain authorization evidence before containment",
        )
        request_evidence = True

    # R7 takes precedence: a dispute matching a clear recurring pattern is not
    # a reason to block the card.
    if facts.recurring_legitimate_pattern:
        should_open_case = True
        _add(
            actions,
            Action.CREATE_CASE,
            facts.exposure_usd,
            "R7: disputed charge matches recurring legitimate pattern",
        )
        _add(
            actions,
            Action.VERIFY_WITH_CUSTOMER,
            facts.exposure_usd,
            "R7: confirm recurring charge with cardholder",
        )
        _add(
            actions,
            Action.WARN_CUSTOMER,
            facts.exposure_usd,
            "R7: provide recurring-charge guidance",
        )
        return PolicyDecision(tuple(actions), True, False, True, False, None, tuple(warnings))

    # R3 settles the investigation.
    if facts.customer_response is CustomerResponse.CONFIRMED:
        _add(
            actions, Action.CLOSE_NO_FRAUD, facts.exposure_usd, "R3: customer confirmed transaction"
        )
        return PolicyDecision(
            tuple(actions),
            should_open_case,
            False,
            False,
            True,
            "Customer confirmation settled the case.",
        )

    # R2: customer denial provides decisive authorization evidence.
    if facts.customer_response is CustomerResponse.DENIED:
        should_open_case = True
        _add(actions, Action.BLOCK_CARD, facts.exposure_usd, "R2: customer denied transaction")
        _add(
            actions,
            Action.CREATE_CASE,
            facts.exposure_usd,
            "R2: unauthorized activity requires internal case",
        )
        if facts.shared_origin or facts.connected_fraud:
            _add(
                actions,
                Action.MONITOR_CONNECTED_CARDS,
                facts.exposure_usd,
                "R2/R6: connected compromise requires monitoring",
            )
        if _must_file_sar(facts):
            _add(
                actions,
                Action.FILE_REPORT,
                facts.exposure_usd,
                "R2: report threshold or shared fraud link met",
            )
        return PolicyDecision(
            tuple(actions),
            True,
            _must_file_sar(facts),
            False,
            True,
            "Customer denial settled authorization.",
        )

    # R4 applies after a verification request has not received a reply.
    if facts.customer_response is CustomerResponse.NO_REPLY_24H:
        _add(actions, Action.MONITOR_CARD, facts.exposure_usd, "R4: no reply within 24 hours")
        if facts.pending_authorization:
            _add(
                actions,
                Action.DECLINE_TRANSACTION,
                facts.exposure_usd,
                "R4: decline pending authorization after no reply",
            )
        if facts.exposure_usd > 500:
            _add(
                actions, Action.ESCALATE_TO_ANALYST, facts.exposure_usd, "R4: exposure exceeds $500"
            )
        return PolicyDecision(tuple(actions), should_open_case, False, False, False, None)

    # R5 has an explicit containment decision even before customer response.
    if facts.card_testing:
        should_open_case = True
        _add(
            actions,
            Action.DECLINE_TRANSACTION,
            facts.exposure_usd,
            "R5: card-testing sequence detected",
        )
        _add(
            actions,
            Action.STEP_UP_AUTH,
            facts.exposure_usd,
            "R5: protect subsequent use after testing sequence",
        )
        if facts.large_testing_purchase_cleared:
            _add(
                actions, Action.BLOCK_CARD, facts.exposure_usd, "R5: purchase over $100 has cleared"
            )

    # R9 is explicit and does not require forced classification.
    if facts.undocumented_coordinated_abuse:
        should_open_case = True
        _add(
            actions,
            Action.CREATE_CASE,
            facts.exposure_usd,
            "R9: documented as coordinated undocumented abuse",
        )
        _add(
            actions,
            Action.FILE_REPORT,
            facts.exposure_usd,
            "R9: coordinated undocumented abuse requires report",
        )
        _add(
            actions,
            Action.ESCALATE_TO_ANALYST,
            facts.exposure_usd,
            "R9: human review required for undocumented pattern",
        )

    # R6: shared origin requires case/report/monitoring when fraud is present.
    if facts.shared_origin and facts.fraud_probability >= 0.70:
        should_open_case = True
        _add(
            actions,
            Action.CREATE_CASE,
            facts.exposure_usd,
            "R6: shared origin across cards identified",
        )
        _add(actions, Action.FILE_REPORT, facts.exposure_usd, "R6: shared origin requires report")
        _add(
            actions,
            Action.MONITOR_CONNECTED_CARDS,
            facts.exposure_usd,
            "R6: monitor every card sharing origin",
        )

    # R10 prevents a sweeping action without the required corroboration.
    if facts.confirmed_fraud_on_two_customer_cards or facts.credentials_confirmed_compromised:
        _add(
            actions, Action.BLOCK_ALL_CARDS, facts.exposure_usd, "R10: all-card block threshold met"
        )

    # R1 and R8 govern uncertainty. A weak single-signal case cannot block.
    weak_signal = facts.evidence_families <= 1 and facts.fraud_probability < 0.70
    if weak_signal:
        should_open_case = True
        request_evidence = True
        _add(
            actions,
            Action.CREATE_CASE,
            facts.exposure_usd,
            "R1: investigation warranted before action",
        )
        _add(
            actions,
            Action.VERIFY_WITH_CUSTOMER,
            facts.exposure_usd,
            "R1: weak signal requires verification before block",
        )
    elif facts.verdict == "uncertain" and (facts.exposure_usd > 500 or facts.conflicting_evidence):
        should_open_case = True
        _add(
            actions,
            Action.CREATE_CASE,
            facts.exposure_usd,
            "R8: uncertain exposed/conflicting case requires a case",
        )
        _add(
            actions,
            Action.ESCALATE_TO_ANALYST,
            facts.exposure_usd,
            "R8: uncertainty with exposure/conflict requires escalation",
        )
    elif facts.fraud_probability <= 0.15 and facts.evidence_families >= 2:
        _add(
            actions,
            Action.CLOSE_NO_FRAUD,
            facts.exposure_usd,
            "Policy 6: low probability supported by independent evidence",
        )
    elif facts.fraud_probability >= 0.85 and facts.evidence_families >= 2:
        should_open_case = True
        _add(
            actions,
            Action.CREATE_CASE,
            facts.exposure_usd,
            "Policy 3a: strong fraud suspicion requires internal case",
        )
        if _must_file_sar(facts):
            _add(actions, Action.FILE_REPORT, facts.exposure_usd, "Policy 3a: SAR threshold met")
        else:
            _add(
                actions,
                Action.MONITOR_CARD,
                facts.exposure_usd,
                "Strong suspicion without report threshold",
            )

    can_stop = (
        facts.fraud_probability >= 0.85 or facts.fraud_probability <= 0.15
    ) and facts.evidence_families >= 2
    stop_reason = (
        "Independent evidence meets the policy confidence threshold." if can_stop else None
    )

    if any(item.action is Action.BLOCK_ALL_CARDS for item in actions) and not (
        facts.confirmed_fraud_on_two_customer_cards or facts.credentials_confirmed_compromised
    ):
        warnings.append(
            "R10 violation prevented: BLOCK_ALL_CARDS requires confirmed compromise threshold."
        )

    return PolicyDecision(
        tuple(actions),
        should_open_case,
        any(item.action is Action.FILE_REPORT for item in actions),
        request_evidence,
        can_stop,
        stop_reason,
        tuple(warnings),
    )
