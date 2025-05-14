import os
import time
import torch
import torch.nn as nn
import torch.optim as optim
from tqdm import tqdm
from phishing_detector.training.data_loader import get_dataloader
from phishing_detector.utils.config import load_skip_indices

class MLP(nn.Module):
    def __init__(self, input_size):
        """
        Initializes a multi-layer perceptron (MLP) with BatchNorm, Dropout, and Sigmoid activation.

        Args:
            input_size (int): Number of input features.
        """
        super(MLP, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 300),
            nn.ReLU(),
            nn.BatchNorm1d(300),
            nn.Dropout(p=0.4),
            nn.Linear(300, 100),
            nn.ReLU(),
            nn.BatchNorm1d(100),
            nn.Linear(100, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.network(x)

def train_model(file_path, batch_size=128, train_ratio=0.9, seed=42, epochs=500, learning_rate=0.001):
    """
    Trains a multi-layer perceptron (MLP) on the given dataset.

    Args:
        file_path (str): Path to the dataset CSV file.
        batch_size (int): Batch size for training. Default is 128.
        train_ratio (float): Ratio of the dataset to use for training. Default is 0.9.
        seed (int): Random seed for reproducibility. Default is 42.
        epochs (int): Number of training epochs. Default is 500.
        learning_rate (float): Learning rate for the optimizer. Default is 0.001.
    """
    exp_dir = f'experiments/{time.strftime("%Y-%m-%d_%H-%M-%S")}'
    os.makedirs(exp_dir, exist_ok=True)
    print(f"Experiment directory: {exp_dir}")

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")

    # Load skip indices
    skip_indices = load_skip_indices(file_path)

    # Load data
    train_loader, eval_loader = get_dataloader(
        file_path, batch_size=batch_size, train_ratio=train_ratio, seed=seed, skip_indices=skip_indices)
    input_size = train_loader.dataset[0][0].shape[0]
    print(f"Input size: {input_size}")

    # Initialize the model, loss function, and optimizer
    model = MLP(input_size).to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=learning_rate)

    def _get_accuracy():
        model.eval()
        correct = 0
        total = 0
        with torch.no_grad():
            for X_batch, y_batch in eval_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                outputs = model(X_batch).squeeze()
                predicted = (outputs >= 0.5).float()
                total += y_batch.size(0)
                correct += (predicted == y_batch).sum().item()
        return 100 * correct / total

    max_acc = 0

    # Training loop
    for epoch in tqdm(range(epochs), desc="Epochs"):
        model.train()
        total_loss = 0
        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device).float()  # Move data to GPU
            optimizer.zero_grad()
            outputs = model(X_batch).squeeze()
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        if (epoch + 1) % 10 == 0:
            tqdm.write(f"Epoch {epoch + 1}/{epochs}, Loss: {total_loss / len(train_loader):.4f}")
            acc = _get_accuracy()
            if max_acc < acc:
                max_acc = acc
                torch.save(model.state_dict(), f'{exp_dir}/best_model.pth')
                tqdm.write(f"Model saved with accuracy: {max_acc:.2f}%")

    return model


if __name__ == "__main__":
    dataset_path = r'datasets/dataset_B_05_2020.csv'
    # model = train_model(file_path=dataset_path, batch_size=128, epochs=500, learning_rate=0.001) # Model saved with accuracy: 89.15%
    # model = train_model(file_path=dataset_path, batch_size=128, epochs=500, learning_rate=0.0001) # Model saved with accuracy: 89.94%
    # model = train_model(file_path=dataset_path, batch_size=32, epochs=500, learning_rate=0.0001) # Model saved with accuracy: 89.76%
    # model = train_model(file_path=dataset_path, batch_size=128, epochs=1000, learning_rate=0.001) # Model saved with accuracy: 90.64%
    # model = train_model(file_path=dataset_path, batch_size=128, epochs=1000, learning_rate=0.0001) # Model saved with accuracy: 90.81%
    # model = train_model(file_path=dataset_path, batch_size=512, epochs=1000, learning_rate=0.0001) # Model saved with accuracy: 90.29%
    # model = train_model(file_path=dataset_path, batch_size=1024, epochs=1000, learning_rate=0.0001) # Model saved with accuracy: 89.15%
    # model = train_model(file_path=dataset_path, batch_size=256, epochs=1000, learning_rate=0.0001) # Model saved with accuracy: 90.73%
    # model = train_model(file_path=dataset_path, batch_size=256, epochs=1000, learning_rate=0.00005) # Model saved with accuracy: 90.90%
    # model = train_model(file_path=dataset_path, batch_size=256, epochs=2000, learning_rate=0.00005) # Model saved with accuracy: 91.95%
    model = train_model(file_path=dataset_path, batch_size=256, epochs=2000, learning_rate=0.00003) # Model saved with accuracy: 92.30%
    # model = train_model(file_path=dataset_path, batch_size=256, epochs=2000, learning_rate=0.00001) # Model saved with accuracy: 92.21%
