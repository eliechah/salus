# ai_filter.py
import tensorflow as tf # type: ignore
from tensorflow.keras.preprocessing.sequence import pad_sequences # type: ignore
import pickle

# Load model and tokenizer once
model = tf.keras.models.load_model("kdnn_model.keras")
with open("tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

MAX_LEN = 100

def is_threat(code_snippet: str) -> bool:
    sequence = tokenizer.texts_to_sequences([code_snippet])
    padded = pad_sequences(sequence, maxlen=MAX_LEN, padding='post', truncating='post')
    prediction = model.predict(padded)[0][0]
    return prediction >= 0.5