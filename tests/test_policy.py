from sentinelgraph.policy import Action, ApprovalRoute, CaseFacts, CustomerResponse, evaluate_policy


def actions_for(facts: CaseFacts) -> set[Action]:
    return {item.action for item in evaluate_policy(facts).actions}


def test_weak_signal_requires_verification_before_block() -> None:
    facts = CaseFacts(0.45, 200, "risk_score", evidence_families=1)
    decision = evaluate_policy(facts)
    assert Action.VERIFY_WITH_CUSTOMER in actions_for(facts)
    assert Action.BLOCK_CARD not in actions_for(facts)
    assert decision.should_request_evidence


def test_customer_denial_blocks_and_reports_shared_origin() -> None:
    facts = CaseFacts(
        0.91,
        268.43,
        "customer_report",
        evidence_families=3,
        verdict="fraud",
        customer_response=CustomerResponse.DENIED,
        shared_origin=True,
    )
    decision = evaluate_policy(facts)
    assert {
        Action.BLOCK_CARD,
        Action.CREATE_CASE,
        Action.FILE_REPORT,
        Action.MONITOR_CONNECTED_CARDS,
    } <= actions_for(facts)
    block = next(item for item in decision.actions if item.action is Action.BLOCK_CARD)
    assert block.route is ApprovalRoute.L1
    assert decision.should_file_sar


def test_customer_confirmation_closes_legitimate() -> None:
    facts = CaseFacts(0.72, 600, "customer_report", 2, customer_response=CustomerResponse.CONFIRMED)
    assert actions_for(facts) == {Action.CLOSE_NO_FRAUD}


def test_card_testing_over_hundred_blocks_card() -> None:
    facts = CaseFacts(
        0.88, 300, "risk_score", 2, card_testing=True, large_testing_purchase_cleared=True
    )
    decision = evaluate_policy(facts)
    assert {Action.DECLINE_TRANSACTION, Action.STEP_UP_AUTH, Action.BLOCK_CARD} <= actions_for(
        facts
    )
    assert (
        next(item for item in decision.actions if item.action is Action.BLOCK_CARD).route
        is ApprovalRoute.L1
    )


def test_r10_all_card_block_requires_high_bar() -> None:
    facts = CaseFacts(0.95, 3000, "risk_score", 3)
    assert Action.BLOCK_ALL_CARDS not in actions_for(facts)
    confirmed = CaseFacts(0.95, 3000, "risk_score", 3, confirmed_fraud_on_two_customer_cards=True)
    decision = evaluate_policy(confirmed)
    all_card = next(item for item in decision.actions if item.action is Action.BLOCK_ALL_CARDS)
    assert all_card.route is ApprovalRoute.L2
