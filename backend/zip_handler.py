import zipfile
import os

def extract_python_files(zip_path, extract_dir):

    os.makedirs(extract_dir, exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

    python_files = []

    for root, dirs, files in os.walk(extract_dir):
        for file in files:
            if file.endswith(".py"):
                python_files.append(os.path.join(root, file))

    return python_files