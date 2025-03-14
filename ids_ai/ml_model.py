import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import numpy as np

class AnomalyDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self._build_model()
        
    def _build_model(self):
        model = tf.keras.Sequential([
            tf.keras.layers.InputLayer(input_shape=(3,)),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(16, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        # Use standard optimizer instead of legacy
        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.AUC()]
        )
        
        self.model = model
    
    def preprocess_data(self, df):
        features = ['length', 'ttl', 'protocol']
        X = df[features].values
        return self.scaler.fit_transform(X)
    
    def train(self, X, epochs=10):
        # For anomaly detection, we need to create artificial labels
        # Normal data is labeled as 0, we'll use this for training
        y = np.zeros(X.shape[0])
        self.model.fit(X, y, epochs=epochs, batch_size=32, verbose=0)
    
    def detect_anomalies(self, X, threshold=0.5):
        # Handle empty input gracefully
        if X is None or len(X) == 0:
            return np.array([]), np.array([])
            
        try:
            # Set verbose=0 to suppress progress bar output
            predictions = self.model.predict(X, verbose=0)
            return predictions > threshold, predictions
        except Exception as e:
            print(f"Error during anomaly detection: {str(e)}")
            # Return empty arrays in case of error
            return np.array([False] * len(X)), np.array([0.0] * len(X))
