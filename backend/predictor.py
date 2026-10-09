import os
import json
import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

from model.hybrid.hybrid_model import HybridModel


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

# Project structure:
#
# project/
# ├── backend/
# └── nids_model/

MODEL_DIR = os.path.join(
    BASE_DIR,
    "nids_model"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "hybrid_cnn_rfnn_v2_final.pt"
)

SCALER_PATH = os.path.join(
    MODEL_DIR,
    "scaler.pkl"
)

FEATURES_PATH = os.path.join(
    MODEL_DIR,
    "features.pkl"
)

CONFIG_PATH = os.path.join(
    MODEL_DIR,
    "config.json"
)


# ============================================================
# DEVICE
# ============================================================

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

print("=" * 70)
print("NIDS MODEL INITIALIZATION")
print("=" * 70)

print("Device:", device)


# ============================================================
# CHECK REQUIRED FILES
# ============================================================

required_files = {
    "model": MODEL_PATH,
    "scaler": SCALER_PATH,
    "features": FEATURES_PATH,
    "config": CONFIG_PATH,
}

for name, path in required_files.items():

    if not os.path.exists(path):

        raise FileNotFoundError(
            f"NIDS {name} file not found:\n{path}"
        )

    print(f"{name:10s}: OK")


# ============================================================
# LOAD CONFIG
# ============================================================

with open(CONFIG_PATH, "r") as f:
    config = json.load(f)

print("Config loaded")


# ============================================================
# LOAD FEATURES
# ============================================================

features_data = joblib.load(
    FEATURES_PATH
)


# Handle possible feature formats

if isinstance(features_data, dict):

    if "features" in features_data:

        FEATURE_NAMES = list(
            features_data["features"]
        )

    elif "feature_names" in features_data:

        FEATURE_NAMES = list(
            features_data["feature_names"]
        )

    else:

        # If dictionary itself is index -> feature
        try:

            FEATURE_NAMES = [
                features_data[k]
                for k in sorted(features_data)
            ]

        except Exception:

            raise ValueError(
                "Unable to determine feature names from features.pkl"
            )

else:

    FEATURE_NAMES = list(
        features_data
    )


EXPECTED_FEATURES = len(
    FEATURE_NAMES
)

print(
    "Features:",
    EXPECTED_FEATURES
)


# ============================================================
# LOAD SCALER
# ============================================================

scaler = joblib.load(
    SCALER_PATH
)

print(
    "Scaler features:",
    scaler.n_features_in_
)


if scaler.n_features_in_ != EXPECTED_FEATURES:

    raise ValueError(
        f"Feature/scaler mismatch: "
        f"{EXPECTED_FEATURES} features but "
        f"scaler expects {scaler.n_features_in_}"
    )


# ============================================================
# CLASS MAPPING
# ============================================================

# IMPORTANT:
#
# These are the EXACT 11 classes and order used during
# the model training.
#
# Do NOT use the old classes.pkl file because that file
# contains an older class mapping.
#
# ============================================================

NUM_CLASSES = 11

ID_TO_CLASS = {

    0: "Benign",

    1: "Bot",

    2: "DDOS attack-HOIC",

    3: "DDoS attacks-LOIC-HTTP",

    4: "DoS attacks-GoldenEye",

    5: "DoS attacks-Hulk",

    6: "DoS attacks-SlowHTTPTest",

    7: "DoS attacks-Slowloris",

    8: "FTP-BruteForce",

    9: "Infilteration",

    10: "SSH-Bruteforce"
}


print(
    "Classes:",
    NUM_CLASSES
)

print(
    "Class mapping:"
)

for class_id in sorted(ID_TO_CLASS):

    print(
        f"  {class_id:02d} -> "
        f"{ID_TO_CLASS[class_id]}"
    )


# ============================================================
# LOAD MODEL CHECKPOINT
# ============================================================

print()

print(
    "Loading model:"
)

print(
    MODEL_PATH
)


checkpoint = torch.load(
    MODEL_PATH,
    map_location=device
)


# ============================================================
# EXTRACT STATE DICT
# ============================================================

if isinstance(checkpoint, dict):

    if "model_state_dict" in checkpoint:

        state_dict = checkpoint[
            "model_state_dict"
        ]

    elif "state_dict" in checkpoint:

        state_dict = checkpoint[
            "state_dict"
        ]

    else:

        # The checkpoint itself may be the state_dict
        state_dict = checkpoint

else:

    raise ValueError(
        "Unsupported checkpoint format."
    )


# ============================================================
# CREATE MODEL
# ============================================================

model = HybridModel(
    num_classes=NUM_CLASSES
).to(device)


# ============================================================
# LOAD WEIGHTS
# ============================================================

model.load_state_dict(
    state_dict
)

model.eval()


# ============================================================
# MODEL INFO
# ============================================================

parameter_count = sum(
    p.numel()
    for p in model.parameters()
)

print(
    "Model loaded successfully."
)

print(
    "Parameters:",
    parameter_count
)

print(
    "Model classes:",
    NUM_CLASSES
)

print(
    "Model ready: True"
)

print("=" * 70)


# ============================================================
# SEVERITY
# ============================================================

def get_severity(
    attack,
    confidence
):

    if attack.lower() == "benign":

        return "Low"

    if confidence >= 95:

        return "Critical"

    elif confidence >= 80:

        return "High"

    elif confidence >= 60:

        return "Medium"

    return "Low"


# ============================================================
# RECOMMENDED ACTION
# ============================================================

def recommended_action(
    attack,
    confidence
):

    attack_lower = attack.lower()

    if attack_lower == "benign":

        return "Allow Traffic"

    if confidence >= 95:

        return "Block Source IP"

    elif confidence >= 80:

        return "Generate Alert"

    return "Monitor Connection"


# ============================================================
# PREDICT ATTACK
# ============================================================

def predict_attack(features):

    # --------------------------------------------------------
    # Validate feature count
    # --------------------------------------------------------

    if len(features) != EXPECTED_FEATURES:

        raise ValueError(
            f"Expected {EXPECTED_FEATURES} features, "
            f"received {len(features)}"
        )


    # --------------------------------------------------------
    # Convert to numeric numpy array
    # --------------------------------------------------------

    try:

        values = np.asarray(
            features,
            dtype=np.float64
        )

    except Exception as e:

        raise ValueError(
            f"Invalid feature values: {e}"
        )


    # --------------------------------------------------------
    # Reshape
    # --------------------------------------------------------

    values = values.reshape(
        1,
        EXPECTED_FEATURES
    )


    # --------------------------------------------------------
    # Handle NaN / Infinity
    # --------------------------------------------------------

    values = np.nan_to_num(
        values,
        nan=0.0,
        posinf=0.0,
        neginf=0.0
    )


    # --------------------------------------------------------
    # Scale
    #
    # Use DataFrame with the original feature names.
    # This removes the sklearn feature-name warning.
    # --------------------------------------------------------

    values_df = pd.DataFrame(
        values,
        columns=FEATURE_NAMES
    )

    scaled = scaler.transform(
        values_df
    )


    # --------------------------------------------------------
    # Convert to tensor
    # --------------------------------------------------------

    tensor = torch.from_numpy(
        scaled.astype(
            np.float32
        )
    ).to(device)


    # --------------------------------------------------------
    # Model inference
    # --------------------------------------------------------

    with torch.inference_mode():

        output = model(
            tensor
        )

        probabilities = F.softmax(
            output,
            dim=1
        )

        confidence_tensor, predicted_tensor = torch.max(
            probabilities,
            dim=1
        )


    # --------------------------------------------------------
    # Prediction ID
    # --------------------------------------------------------

    predicted_id = int(
        predicted_tensor.item()
    )


    # --------------------------------------------------------
    # Confidence
    # --------------------------------------------------------

    confidence = float(
        confidence_tensor.item() * 100
    )

    confidence = round(
        confidence,
        2
    )


    # --------------------------------------------------------
    # Class
    # --------------------------------------------------------

    if predicted_id not in ID_TO_CLASS:

        attack = f"Unknown_{predicted_id}"

    else:

        attack = ID_TO_CLASS[
            predicted_id
        ]


    # --------------------------------------------------------
    # Severity
    # --------------------------------------------------------

    severity = get_severity(
        attack,
        confidence
    )


    # --------------------------------------------------------
    # Action
    # --------------------------------------------------------

    action = recommended_action(
        attack,
        confidence
    )


    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {

        "class_id": predicted_id,

        "attack": attack,

        "confidence": confidence,

        "severity": severity,

        "action": action
    }


# ============================================================
# STARTUP TEST
# ============================================================

if __name__ == "__main__":

    print()

    print("=" * 70)
    print("NIDS PREDICTOR TEST")
    print("=" * 70)

    print(
        "Device:",
        device
    )

    print(
        "Features:",
        EXPECTED_FEATURES
    )

    print(
        "Classes:",
        NUM_CLASSES
    )

    print(
        "Model:",
        os.path.basename(MODEL_PATH)
    )


    # --------------------------------------------------------
    # Dummy 78-feature vector
    # --------------------------------------------------------

    sample = [
        0.0
    ] * EXPECTED_FEATURES


    try:

        result = predict_attack(
            sample
        )

        print()

        print(
            "Prediction:"
        )

        print(
            result
        )

    except Exception as e:

        print()

        print(
            "Prediction ERROR:"
        )

        print(
            repr(e)
        )