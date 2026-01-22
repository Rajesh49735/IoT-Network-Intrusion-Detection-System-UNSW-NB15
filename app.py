# Determine feature size
if hasattr(model, "n_features_in_"):
    n_features = model.n_features_in_
else:
    n_features = model.coefs_[0].shape[0]

# Create feature vector
input_data = np.zeros((1, n_features), dtype=float)

# Base features
input_data[0, 0] = spkts
input_data[0, 1] = dpkts
input_data[0, 2] = sbytes
input_data[0, 3] = dbytes

# Derived features (example)
input_data[0, 4] = spkts + dpkts                # total packets
input_data[0, 5] = sbytes + dbytes              # total bytes
input_data[0, 6] = sbytes / (spkts + 1)          # avg src bytes/packet
input_data[0, 7] = dbytes / (dpkts + 1)
input_data[0, 8] = abs(spkts - dpkts)
input_data[0, 9] = abs(sbytes - dbytes)

# Fill remaining features with small noise
input_data[0, 10:] = np.random.normal(0, 0.01, n_features - 10)

