import json
import os

def load_skip_indices(dataset_path):
    """
    Loads skip indices from a JSON file located next to the dataset.

    Args:
        dataset_path (str): Path to the dataset CSV file.

    Returns:
        list: List of column indices to skip.
    """
    config_path = os.path.splitext(dataset_path)[0] + "_config.json"
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, "r") as f:
        config = json.load(f)
    
    return config.get("skip_indices", [])
