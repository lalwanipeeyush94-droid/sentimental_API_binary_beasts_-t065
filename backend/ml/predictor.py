import os
import joblib
import pandas as pd

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "model.pkl"
)

model = joblib.load(MODEL_PATH)


METHOD_MAP = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "PATCH": 3,
    "DELETE": 4,
    "WS": 5,
    "GRPC": 6,
}


RESOURCE_KEYWORDS = [
    "order",
    "user",
    "account",
    "invoice",
    "payment",
    "profile",
    "resource",
    "record",
    "channel",
]


def extract_features(
    path: str,
    method: str = "GET",
    summary: str = "",
    api_type: str = "REST",
):
    path_lower = path.lower()
    summary_lower = str(summary).lower()

    text = path_lower + " " + summary_lower

    method_code = METHOD_MAP.get(
        method.upper(),
        0
    )

    # Example:
    # /orders/{order_id}
    has_id = int(
        "{" in path
        and "}" in path
    )

    id_in_path = int(
        has_id
        or any(
            keyword in text
            for keyword in RESOURCE_KEYWORDS
        )
    )

    sensitive_resource = int(
        any(
            keyword in text
            for keyword in RESOURCE_KEYWORDS
        )
    )

    # Important for live OpenAPI inference.
    # Resource identifiers such as order_id/user_id
    # are authorization-sensitive objects.
    access_control = int(
        has_id
        or any(
            keyword in text
            for keyword in [
                "access",
                "authorization",
                "authorize",
                "permission",
                "owner",
                "private",
                "resource",
                "account",
            ]
        )
    )

    return {
        "method_code": method_code,
        "has_id": has_id,
        "id_in_path": id_in_path,
        "sensitive_resource": sensitive_resource,
        "access_control": access_control,
        "api_type": api_type,
    }


def predict_endpoint(
    path: str,
    method: str = "GET",
    summary: str = "",
    api_type: str = "REST",
):
    feature_data = extract_features(
        path=path,
        method=method,
        summary=summary,
        api_type=api_type,
    )

    df = pd.DataFrame([
        feature_data
    ])

    probability = model.predict_proba(df)[0][1]

    if probability >= 0.75:
        priority = "HIGH"
    elif probability >= 0.45:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    return {
        "path": path,
        "method": method.upper(),
        "bola_probability": round(
            float(probability),
            4
        ),
        "priority": priority,
    }


if __name__ == "__main__":

    test_endpoints = [
        ("/orders/{order_id}", "GET"),
        ("/users/{user_id}", "GET"),
        ("/health", "GET"),
        ("/products", "GET"),
    ]

    print(
        "\n--- SentinelAPI Kaggle MLP Prediction ---"
    )

    for path, method in test_endpoints:

        result = predict_endpoint(
            path=path,
            method=method
        )

        print(
            f"{method:6} "
            f"{path:25} "
            f"Probability: "
            f"{result['bola_probability']:.4f} "
            f"| Priority: "
            f"{result['priority']}"
        )