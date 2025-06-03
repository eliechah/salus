import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import pickle

model = tf.keras.models.load_model("kdnn_model.keras")
with open("tokenizer.pkl", "rb") as f:
    tokenizer = pickle.load(f)

MAX_LEN = 100

def is_threat(code_snippet: str) -> bool:
    sequence = tokenizer.texts_to_sequences([code_snippet])
    padded = pad_sequences(sequence, maxlen=MAX_LEN, padding='post', truncating='post')
    prediction = model.predict(padded, verbose=0)[0][0]
    return prediction >= 0.4
