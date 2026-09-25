import json
import os
import pandas as pd

DATA_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "data",
    "API_MISCONFIGURATION_DATASET.jsonl",
)

OUTPUT_PATH = os.path.join(
    os.path.dirname(__file__),
    "kaggle_bola_dataset.csv",
)


METHOD_MAP = {
    "GET": 0,
    "POST": 1,
    "PUT": 2,
    "PATCH": 3,
    "DELETE": 4,
    "WS": 5,
    "GRPC": 6,
}


def extract_features(
    endpoint: str,
    title: str,
    category: str,
    risk: str,
    api_type: str,
):
    text = " ".join([
        str(endpoint),
        str(title),
        str(category),
        str(risk),
    ]).lower()

    method = str(endpoint).split(" ")[0].upper()

    method_code = METHOD_MAP.get(method, 0)

    has_id = int(
        "{" in str(endpoint)
        and "}" in str(endpoint)
    )

    id_in_path = int(
        any(
            keyword in text
            for keyword in [
                "id",
                "order",
                "user",
                "account",
                "payment",
                "profile",
                "resource",
                "record",
                "channel",
            ]
        )
    )

    sensitive_resource = int(
        any(
            keyword in text
            for keyword in [
                "order",
                "payment",
                "profile",
                "account",
                "user",
                "record",
                "data",
                "channel",
            ]
        )
    )

    access_control = int(
        "access control" in text
        or "authorization" in text
        or "unauthorized access" in text
        or "unauthorized modification" in text
        or "unauthorized deletion" in text
    )

    bola = int(
        "bola" in text
        or "broken object level authorization" in text
    )

    return {
        "method_code": method_code,
        "has_id": has_id,
        "id_in_path": id_in_path,
        "sensitive_resource": sensitive_resource,
        "access_control": access_control,
        "api_type": str(api_type),
        "bola": bola,
    }


def add_controlled_bola_examples(rows):
    """
    Controlled examples representing the type of BOLA
    SentinelAPI is designed to detect.

    These are NOT claimed to come from Kaggle.
    They are local training examples for our prototype.
    """

    positive_examples = [
        ("GET", "/orders/{order_id}", "REST"),
        ("GET", "/users/{user_id}", "REST"),
        ("GET", "/payments/{payment_id}", "REST"),
        ("GET", "/profiles/{profile_id}", "REST"),
        ("GET", "/accounts/{account_id}", "REST"),
        ("GET", "/records/{record_id}", "REST"),
        ("GET", "/resources/{resource_id}", "REST"),
        ("GET", "/channels/{channel_id}", "REST"),
        ("POST", "/orders/{order_id}", "REST"),
        ("PATCH", "/orders/{order_id}", "REST"),
        ("DELETE", "/orders/{order_id}", "REST"),
        ("GET", "/invoices/{invoice_id}", "REST"),
    ]

    negative_examples = [
        ("GET", "/health", "REST"),
        ("GET", "/products", "REST"),
        ("GET", "/categories", "REST"),
        ("GET", "/public/news", "REST"),
        ("GET", "/status", "REST"),
        ("GET", "/version", "REST"),
        ("GET", "/search", "REST"),
        ("GET", "/docs", "REST"),
        ("GET", "/metrics", "REST"),
        ("GET", "/products/{product_id}", "REST"),
        ("GET", "/categories/{category_id}", "REST"),
        ("GET", "/public/{page_id}", "REST"),
    ]

    for method, endpoint, api_type in positive_examples:
        features = extract_features(
            endpoint=endpoint,
            title="Broken Object Level Authorization",
            category="Access Control",
            risk="Unauthorized Access",
            api_type=api_type,
        )
        rows.append(features)

    for method, endpoint, api_type in negative_examples:
        features = extract_features(
            endpoint=endpoint,
            title="Public API Endpoint",
            category="General",
            risk="Low Risk",
            api_type=api_type,
        )
        features["bola"] = 0
        rows.append(features)


def main():

    with open(DATA_PATH, "r", encoding="utf-8") as file:
        data = json.load(file)

    rows = []

    # Kaggle dataset
    for item in data:
        features = extract_features(
            endpoint=item.get("endpoint", ""),
            title=item.get("title", ""),
            category=item.get("category", ""),
            risk=item.get("risk", ""),
            api_type=item.get("api_type", ""),
        )

        rows.append(features)

    kaggle_count = len(rows)
    kaggle_bola = sum(row["bola"] for row in rows)

    # Controlled SentinelAPI examples
    add_controlled_bola_examples(rows)

    df = pd.DataFrame(rows)

    df.to_csv(
        OUTPUT_PATH,
        index=False,
    )

    print("\n========================================")
    print(" SentinelAPI BOLA Dataset Preparation")
    print("========================================")

    print("Original Kaggle records:", kaggle_count)
    print("Original Kaggle BOLA:", kaggle_bola)

    print(
        "Controlled examples added:",
        len(df) - kaggle_count
    )

    print(
        "Controlled BOLA examples:",
        12
    )

    print("\nFinal training records:", len(df))
    print("Final BOLA records:", int(df["bola"].sum()))
    print(
        "Final Non-BOLA records:",
        int((df["bola"] == 0).sum())
    )

    print("\nSaved:")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()