#!/bin/bash

# ================================
# Kaggle Dataset Download Script
# ================================

# Replace with your Kaggle dataset path
KAGGLE_DATASET="devanandsrinivasan/mwai-5k"

# Target directory
DATASET_DIR="datasets"

echo "======================================"
echo "Downloading dataset from Kaggle..."
echo "Dataset: $KAGGLE_DATASET"
echo "======================================"

# Check if kaggle is installed
if ! command -v kaggle &> /dev/null
then
    echo "? Kaggle CLI not found."
    echo "?? Install it using: pip install kaggle"
    exit 1
fi

# Check if Kaggle API key exists
if [ ! -f "$HOME/.kaggle/kaggle.json" ]; then
    echo "? Kaggle API key not found."
    echo "?? Place kaggle.json in ~/.kaggle/ and set permissions:"
    echo "   chmod 600 ~/.kaggle/kaggle.json"
    exit 1
fi

# Create dataset directory
mkdir -p $DATASET_DIR
cd $DATASET_DIR || exit

# Download dataset
kaggle datasets download -d $KAGGLE_DATASET

# Unzip dataset
ZIP_FILE=$(ls *.zip | head -n 1)
unzip -o "$ZIP_FILE"

echo "? Dataset downloaded and extracted successfully."
echo "?? Location: $(pwd)"

