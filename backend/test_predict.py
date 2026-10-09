# backend/test_predict.py

from backend.predictor import predict_attack

features = [0.0] * 78

result = predict_attack(features)

print("Result:", result)