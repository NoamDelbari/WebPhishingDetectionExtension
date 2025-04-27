import pandas as pd
import torch
from torch.utils.data import DataLoader, TensorDataset, random_split

def get_dataloader(file_path, batch_size=32, shuffle=True, train_ratio=0.9, seed=42, skip_indices=[]):
    """
    Loads a dataset from a CSV file, splits it into train and eval sets, and returns DataLoaders.

    Args:
        file_path (str): Path to the CSV file.
        batch_size (int): Batch size for the DataLoader. Default is 32.
        shuffle (bool): Whether to shuffle the dataset. Default is True.
        train_ratio (float): Ratio of the dataset to use for training. Default is 0.9.
        seed (int): Random seed for reproducibility. Default is 42.

    Returns:
        tuple: A tuple containing train DataLoader and eval DataLoader.
    """
    # Step 1: Read the CSV file
    data = pd.read_csv(file_path)

    # Step 2: Split features and labels
    valid_indices = [i for i in range(len(data.columns)-1) if i not in skip_indices]
    X = data.iloc[:, valid_indices].values  # All columns except the last one and first one (index 0)
    # Convert labels from 'phishing' and 'legitimate' to 1 and 0
    y = data.iloc[:, -1].apply(lambda label: 1 if label == 'phishing' else 0).values

    # Step 3: Convert to PyTorch tensors
    X_tensor = torch.tensor(X, dtype=torch.float32)  # Features as float32
    y_tensor = torch.tensor(y, dtype=torch.long)     # Labels as long (for classification)

    # Step 4: Create a TensorDataset
    dataset = TensorDataset(X_tensor, y_tensor)

    # Step 5: Split the dataset into train and eval sets
    train_size = int(len(dataset) * train_ratio)
    eval_size = len(dataset) - train_size
    torch.manual_seed(seed)  # Set the random seed for reproducibility
    train_dataset, eval_dataset = random_split(dataset, [train_size, eval_size])

    # Step 6: Create DataLoaders for train and eval sets
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=shuffle)
    eval_loader = DataLoader(eval_dataset, batch_size=batch_size, shuffle=False)

    return train_loader, eval_loader

