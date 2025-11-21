"""
Utility functions for ML training pipeline.
"""

import os
import json
import pickle
from datetime import datetime
from typing import Any, Dict


def ensure_dir(directory: str) -> None:
    """
    Create directory if it doesn't exist.
    
    Args:
        directory: Path to directory
    """
    os.makedirs(directory, exist_ok=True)


def save_pickle(obj: Any, filepath: str) -> None:
    """
    Save object to pickle file.
    
    Args:
        obj: Object to save
        filepath: Path to save file
    """
    ensure_dir(os.path.dirname(filepath))
    with open(filepath, 'wb') as f:
        pickle.dump(obj, f)
    print(f"✓ Saved pickle: {filepath}")


def load_pickle(filepath: str) -> Any:
    """
    Load object from pickle file.
    
    Args:
        filepath: Path to pickle file
        
    Returns:
        Loaded object
    """
    with open(filepath, 'rb') as f:
        return pickle.load(f)


def save_json(data: Dict, filepath: str) -> None:
    """
    Save dictionary to JSON file.
    
    Args:
        data: Dictionary to save
        filepath: Path to save file
    """
    ensure_dir(os.path.dirname(filepath))
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    print(f"✓ Saved JSON: {filepath}")


def load_json(filepath: str) -> Dict:
    """
    Load dictionary from JSON file.
    
    Args:
        filepath: Path to JSON file
        
    Returns:
        Loaded dictionary
    """
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)


def get_timestamp() -> str:
    """
    Get current timestamp string.
    
    Returns:
        Timestamp in format YYYY-MM-DD_HH-MM-SS
    """
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def print_section(title: str) -> None:
    """
    Print formatted section header.
    
    Args:
        title: Section title
    """
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)


def print_metrics(metrics: Dict[str, float]) -> None:
    """
    Print model evaluation metrics in formatted table.
    
    Args:
        metrics: Dictionary of metric names and values
    """
    print("\nModel Performance Metrics:")
    print("-" * 40)
    for metric, value in metrics.items():
        print(f"  {metric:20s}: {value:.4f}")
    print("-" * 40)


def format_size(size_bytes: int) -> str:
    """
    Format byte size to human-readable string.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def validate_file_exists(filepath: str, file_description: str = "File") -> None:
    """
    Validate that a file exists, raise error if not.
    
    Args:
        filepath: Path to file
        file_description: Description of file for error message
        
    Raises:
        FileNotFoundError: If file doesn't exist
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(
            f"{file_description} not found: {filepath}\n"
            f"Please ensure the file exists before running."
        )


def get_file_size(filepath: str) -> int:
    """
    Get file size in bytes.
    
    Args:
        filepath: Path to file
        
    Returns:
        File size in bytes
    """
    return os.path.getsize(filepath)
