from backend.realtime.feature_extractor import FeatureExtractor
from backend.predictor import predict_attack


# =====================================================
# REALTIME FLOW PREDICTION
# =====================================================

def predict_flow(flow):

    # -------------------------------------------------
    # Generate 78 CIC-IDS2018 features
    # -------------------------------------------------

    extractor = FeatureExtractor(flow)

    features = extractor.basic_features()

    # -------------------------------------------------
    # Safety check
    # -------------------------------------------------

    if len(features) != 78:

        raise ValueError(
            f"FeatureExtractor generated "
            f"{len(features)} features. "
            f"Expected 78."
        )

    # -------------------------------------------------
    # DEBUG: PRINT REALTIME FEATURES
    # -------------------------------------------------

    print("\n" + "=" * 70)
    print("REALTIME FLOW FEATURES")
    print("=" * 70)

    for i, value in enumerate(features, 1):

        try:
            print(
                f"{i:02d}. {float(value):.6f}"
            )

        except Exception:
            print(
                f"{i:02d}. {value}"
            )

    print("=" * 70)

    # -------------------------------------------------
    # V2 MODEL PREDICTION
    # -------------------------------------------------

    result = predict_attack(
        features
    )

    # -------------------------------------------------
    # Return result
    # -------------------------------------------------

    return result