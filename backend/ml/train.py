import os

import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)


DATA_PATH = os.path.join(
    os.path.dirname(__file__),
    "kaggle_bola_dataset.csv",
)

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "model.pkl",
)


def main():

    # ============================================================
    # 1. LOAD KAGGLE DATASET
    # ============================================================

    df = pd.read_csv(DATA_PATH)

    print("\n========================================")
    print(" SentinelAPI Kaggle MLP Training")
    print("========================================")

    print(
        "Total records:",
        len(df),
    )

    print(
        "BOLA records:",
        int(df["bola"].sum()),
    )

    print(
        "Non-BOLA records:",
        int((df["bola"] == 0).sum()),
    )


    # ============================================================
    # 2. FEATURES
    # ============================================================

    feature_columns = [
        "method_code",
        "has_id",
        "id_in_path",
        "sensitive_resource",
        "access_control",
        "api_type",
    ]

    X = df[feature_columns]

    y = df["bola"]


    # ============================================================
    # 3. TRAIN / TEST SPLIT
    # ============================================================

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )


    # ============================================================
    # 4. PREPROCESSING
    # ============================================================

    numeric_features = [
        "method_code",
        "has_id",
        "id_in_path",
        "sensitive_resource",
        "access_control",
    ]

    categorical_features = [
        "api_type",
    ]

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "numeric",
                StandardScaler(),
                numeric_features,
            ),
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore"
                ),
                categorical_features,
            ),
        ]
    )


    # ============================================================
    # 5. NEURAL NETWORK
    # ============================================================

    model = MLPClassifier(
        hidden_layer_sizes=(16, 8),
        activation="relu",
        solver="adam",
        max_iter=1500,
        random_state=42,
    )


    # ============================================================
    # 6. COMPLETE PIPELINE
    # ============================================================

    pipeline = Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor,
            ),
            (
                "neural_network",
                model,
            ),
        ]
    )


    # ============================================================
    # 7. TRAIN
    # ============================================================

    pipeline.fit(
        X_train,
        y_train,
    )


    # ============================================================
    # 8. PREDICTION
    # ============================================================

    y_pred = pipeline.predict(
        X_test
    )


    # ============================================================
    # 9. EVALUATION
    # ============================================================

    accuracy = accuracy_score(
        y_test,
        y_pred,
    )

    print(
        "\nTraining samples:",
        len(X_train),
    )

    print(
        "Testing samples:",
        len(X_test),
    )

    print(
        "\nAccuracy:",
        round(accuracy, 4),
    )

    print(
        "\nClassification Report:"
    )

    print(
        classification_report(
            y_test,
            y_pred,
            zero_division=0,
        )
    )

    print(
        "Confusion Matrix:"
    )

    print(
        confusion_matrix(
            y_test,
            y_pred,
        )
    )


    # ============================================================
    # 10. SAVE MODEL
    # ============================================================

    joblib.dump(
        pipeline,
        MODEL_PATH,
    )

    print(
        "\nModel saved successfully:"
    )

    print(
        MODEL_PATH
    )


if __name__ == "__main__":
    main()