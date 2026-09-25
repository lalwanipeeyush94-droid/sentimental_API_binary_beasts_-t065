from typing import List, Dict

ALLOWED_METHODS = {
    "GET"
}


def plan_next_test(
    endpoints: List[Dict]
):
    """
    Select the next safe endpoint to test.

    Expected endpoint format:
    {
        "endpoint_id": 1,
        "path": "/orders/{order_id}",
        "method": "GET",
        "ml_probability": 0.95,
        "priority": "HIGH",
        "resource_id": "B204"
    }
    """

    candidates = []

    for endpoint in endpoints:
        method = endpoint.get("method", "").upper()

        if method not in ALLOWED_METHODS:
            continue

        resource_id = endpoint.get("resource_id")

        if not resource_id:
            continue

        candidates.append(endpoint)

    if not candidates:
        return {
            "action": "STOP",
            "reason": "No safe test candidate available",
            "endpoint": None,
        }

    candidates.sort(
        key=lambda item: item.get("ml_probability", 0),
        reverse=True
    )

    selected = candidates[0]

    plan = {
        "action": "TEST_BOLA",
        "endpoint_id": selected.get("endpoint_id"),
        "path": selected.get("path"),
        "method": selected.get("method"),
        "resource_id": selected.get("resource_id"),
        "ml_probability": selected.get("ml_probability"),
        "priority": selected.get("priority"),
        "owner_identity": "alice",
        "test_identity": "bob",
        "reason": (
            "Endpoint selected because "
            "the Neural Network assigned it "
            "a high BOLA-testing priority."
        ),
    }

    return plan


if __name__ == "__main__":

    sample_endpoints = [
        {
            "endpoint_id": 1,
            "path": "/orders/{order_id}",
            "method": "GET",
            "ml_probability": 1.00,
            "priority": "HIGH",
            "resource_id": "B204",
        },
        {
            "endpoint_id": 2,
            "path": "/health",
            "method": "GET",
            "ml_probability": 0.00,
            "priority": "LOW",
            "resource_id": None,
        },
    ]

    plan = plan_next_test(sample_endpoints)

    print("\n--- SentinelAPI Agent Planner ---")
    print("Action:", plan["action"])
    print("Endpoint:", plan.get("path"))
    print("Method:", plan.get("method"))
    print("Resource:", plan.get("resource_id"))
    print("ML Probability:", plan.get("ml_probability"))
    print("Priority:", plan.get("priority"))
    print("Owner:", plan.get("owner_identity"))
    print("Test Identity:", plan.get("test_identity"))
    print("Reason:", plan.get("reason"))