from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import pickle
import os
import validators
import requests
import pandas as pd
from feature_extractor import extract_features

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

# Load the pickled model with warning suppression
import warnings
from sklearn.exceptions import InconsistentVersionWarning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

model_path = "model/resmlp_phishing_model.pkl"
with open(model_path, 'rb') as f:
    model = pickle.load(f)
print("Loaded pickled model from:", model_path)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form['url']
        print("Received URL:", url)
        
        # Extract features for debugging
        features = extract_features(url)
        print("Extracted features:")
        print(features)
        
        # Remove "http://" or "https://" if present for prediction
        if url.lower().startswith("http://"):
            new_url = url[len("http://"):]
        elif url.lower().startswith("https://"):
            new_url = url[len("https://"):]
        else:
            new_url = url
        print("URL used for prediction (without scheme):", new_url)
        
        # Use the new URL (without the scheme) for prediction
        prediction = model.predict([new_url])
        predicted_value = prediction[0]
        
        # If the prediction is numeric, convert it; otherwise, use as is
        try:
            predicted_class = int(predicted_value)
            result = "Phishing" if predicted_class == 1 else "Legitimate"
        except ValueError:
            result = predicted_value
        
        print("Prediction:", result)
        return jsonify({'result': result})
    
    except Exception as e:
        print("Error:", str(e))
        return jsonify({'error': str(e)}), 500

@app.route('/save', methods=['POST'])
def save():
    """
    Receives JSON with { "url": "...", "result": "..." }
    Appends it to 'results.xlsx' (2 columns: URL, Result).
    """
    data = request.get_json()
    url = data.get('url', '')
    result = data.get('result', '')

    file_path = 'results.xlsx'

    # If file exists, load it. Otherwise, create a new DataFrame
    if os.path.exists(file_path):
        df = pd.read_excel(file_path)
    else:
        df = pd.DataFrame(columns=['URL', 'Result'])

    # Append new row using pd.concat
    new_row = {'URL': url, 'Result': result}
    df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)

    # Save back to Excel
    df.to_excel(file_path, index=False)

    return jsonify({'message': 'Result saved successfully!'})

if __name__ == '__main__':
    # Get the port from the environment variable
    port = int(os.environ.get('PORT', 5000))
    # Bind to 0.0.0.0 to make it accessible from outside the container
    app.run(host='0.0.0.0', port=port, debug=True)