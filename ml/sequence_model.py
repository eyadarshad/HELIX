"""
sequence_model.py – LSTM / 1D CNN sequence classifier (Week 5 – Advanced ML).

Encodes opcode sequences from the JSON dataset and trains a neural network
to classify programs using temporal patterns.

Usage:
    python -m ml.sequence_model

Requires: tensorflow  (pip install tensorflow)
"""

import json
import os
import numpy as np
from collections import Counter

SEQUENCE_JSON = "dataset/sequence_dataset.json"
MODELS_DIR    = "ml/models"
MAX_SEQ_LEN   = 200   # truncate/pad all sequences to this length


OPCODES = [
    "PAD", "MOV", "ADD", "SUB", "MUL", "DIV", "AND", "OR", "XOR", "NOT",
    "CMP", "PUSH", "POP", "JMP", "JZ", "JNZ", "JG", "JL",
    "CALL", "RET", "INT", "NOP", "HLT", "UNK",
]
OPCODE2IDX = {op: i for i, op in enumerate(OPCODES)}
VOCAB_SIZE  = len(OPCODES)


def encode_sequence(seq: list[str], max_len: int = MAX_SEQ_LEN) -> list[int]:
    """Convert opcode strings → integer indices, truncate/pad."""
    ids = [OPCODE2IDX.get(op.upper(), OPCODE2IDX["UNK"]) for op in seq]
    ids = ids[:max_len]
    ids += [0] * (max_len - len(ids))  # pad with 0 = PAD
    return ids


def load_sequence_data():
    with open(SEQUENCE_JSON) as f:
        data = json.load(f)

    X = np.array([encode_sequence(d["sequence"]) for d in data])
    y = np.array([1 if d["label"] == "malware" else 0 for d in data])
    return X, y


def build_lstm_model(vocab_size: int, seq_len: int):
    """Build a simple LSTM classification model."""
    try:
        import tensorflow as tf
        from tensorflow.keras import layers, models
    except ImportError:
        raise ImportError("Install tensorflow: pip install tensorflow")

    m = models.Sequential([
        layers.Embedding(vocab_size, 32, input_length=seq_len),
        layers.LSTM(64, return_sequences=True),
        layers.LSTM(32),
        layers.Dense(32, activation="relu"),
        layers.Dropout(0.3),
        layers.Dense(1, activation="sigmoid"),
    ])
    m.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return m


def build_cnn_model(vocab_size: int, seq_len: int):
    """Build a 1D CNN classification model."""
    try:
        import tensorflow as tf
        from tensorflow.keras import layers, models
    except ImportError:
        raise ImportError("Install tensorflow: pip install tensorflow")

    m = models.Sequential([
        layers.Embedding(vocab_size, 32, input_length=seq_len),
        layers.Conv1D(64, kernel_size=3, activation="relu"),
        layers.GlobalMaxPooling1D(),
        layers.Dense(64, activation="relu"),
        layers.Dropout(0.3),
        layers.Dense(1, activation="sigmoid"),
    ])
    m.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return m


def train_sequence_model(model_type: str = "lstm"):
    """Train and evaluate the sequence model."""
    import tensorflow as tf
    from sklearn.model_selection import train_test_split

    print(f"[+] Loading sequence dataset...")
    X, y = load_sequence_data()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    if model_type == "lstm":
        model = build_lstm_model(VOCAB_SIZE, MAX_SEQ_LEN)
    else:
        model = build_cnn_model(VOCAB_SIZE, MAX_SEQ_LEN)

    model.summary()
    print(f"\n[+] Training {model_type.upper()} model...")

    history = model.fit(
        X_train, y_train,
        validation_split=0.1,
        epochs=15,
        batch_size=32,
        verbose=1,
    )

    loss, acc = model.evaluate(X_test, y_test, verbose=0)
    print(f"\n[{model_type.upper()}] Test Accuracy: {acc:.4f}  Loss: {loss:.4f}")

    os.makedirs(MODELS_DIR, exist_ok=True)
    save_path = os.path.join(MODELS_DIR, f"{model_type}_model.keras")
    model.save(save_path)
    print(f"[+] Model saved → {save_path}")
    return model, history


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=["lstm", "cnn"], default="lstm")
    args = parser.parse_args()
    train_sequence_model(args.model)
