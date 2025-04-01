from feature_extractor import extract_features_debug

url = "https://open.spotify.com/"
features = extract_features_debug(url)
print("Extracted features for", url)
for key, value in features.items():
    print(f"{key}: {value}")
