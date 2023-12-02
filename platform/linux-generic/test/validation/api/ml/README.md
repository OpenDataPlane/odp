# How to run ML validation test

Simple onnx models are used to test ML API.

## Generate models

### Install python requirements

```bash
python3 -m pip install -r <this directory>/requirements.txt
```

### Generate models for validation tests

```bash
<this directory>/gen_models.sh
```

## Run ML validation tests

```bash
<this directory>/ml_linux
```
