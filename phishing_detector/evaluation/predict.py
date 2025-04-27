import os
import torch
import pandas as pd
from phishing_detector.training.train import FullyConnectedNetwork
from phishing_detector.utils.config import load_skip_indices  # Import the utility function

_model_cache = None  # Cache for the loaded model

def load_model(exp_name, input_size, hidden_size, output_size=2):
    """
    Loads a saved model from the specified experiment directory.

    Args:
        exp_name (str): Name of the experiment directory.
        input_size (int): Number of input features.
        hidden_size (int): Number of neurons in the hidden layer.
        output_size (int): Number of output classes. Default is 2.

    Returns:
        nn.Module: The loaded model.
    """
    global _model_cache
    if _model_cache is None:
        model_path = os.path.join("experiments", exp_name, "best_model.pth")
        model = FullyConnectedNetwork(input_size, hidden_size, output_size)
        model.load_state_dict(torch.load(model_path))
        model.eval()
        _model_cache = model
    return _model_cache

def predict(vector, exp_name, input_size, hidden_size):
    """
    Predicts the label ("phishing" or "legitimate") for a given feature vector.

    Args:
        vector (list or numpy array): Feature vector to predict.
        exp_name (str): Name of the experiment directory.
        input_size (int): Number of input features.
        hidden_size (int): Number of neurons in the hidden layer.

    Returns:
        str: Predicted label ("phishing" or "legitimate").
    """
    # Load the model (singleton)
    model = load_model(exp_name, input_size, hidden_size)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    # Convert the vector to a PyTorch tensor and move to device
    vector_tensor = torch.tensor(vector, dtype=torch.float32).to(device).unsqueeze(0)

    # Make prediction
    with torch.no_grad():
        outputs = model(vector_tensor)
        _, predicted = torch.max(outputs, 1)

    return "phishing" if predicted.item() == 1 else "legitimate"

if __name__ == "__main__":
    # Example usage
    dataset_path = r'datasets/dataset_B_05_2020.csv'
    exp_name = "2025-04-27_19-36-27"  # Replace with the actual experiment name
    skip_indices = load_skip_indices(dataset_path)  # Load skip indices from the config file
    hidden_size = 256

    # Load a sample vector from the dataset
    data = pd.read_csv(dataset_path)
    sample_vector = data.iloc[0, 1:-1].values.tolist()  # Skip the first column and the label column
    input_size = len(sample_vector)

    prediction = predict(sample_vector, exp_name, input_size, hidden_size)
    print("Prediction:", prediction)
