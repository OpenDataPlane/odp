# ML examples

Machine Learning API examples demonstrate how to use ODP ML API in different tasks:
for example simple linear computation and predicting a handwritten digit in
a given image.

## Simple Linear

This example runs on a very simple model of form y = 3 * x + 4 where x is given
as the second argument.

### Generate model

```bash
python3 <odp_directory>/platform/linux-generic/test/validation/api/ml/simple_linear_gen.py
```

### Run simple linear

```bash
$ ./simple_linear 3
.
.
.
y = 3 * 3 + 4: 13
.
```

Or run the program with multiple threads, each thread inferences on one x given in
the input. Thus, the number of threads is the number of numbers in the second argument.

```bash
$ ./simple_linear [2,4,5]
.
.
.
y = 3 * 2 + 4: 10
y = 3 * 5 + 4: 19
y = 3 * 4 + 4: 16
.
```

## MNIST

This example predicts a handwritten digit in a given image. Refer to
https://github.com/onnx/models/tree/main/validated/vision/classification/mnist
for more information. The model file is from
https://github.com/onnx/models/raw/main/validated/vision/classification/mnist/model/mnist-12.onnx
(SPDX-License-Identifier: MIT).

### Prepare input data

The input image is stored in a csv file which contains, comma separated, the
digit label (a number from 0 to 9) and the 784 pixel values (a number from 0 to
255). Pixel order is left to right and then top down. The MNIST dataset is
available in this format at https://www.kaggle.com/oddrationale/mnist-in-csv.

### Run mnist

```bash
$ ./mnist mnist-12.onnx example_digit.csv
.
.
.
predicted_digit: 4, expected_digit: 4
.
```

## Model Explorer

The example prints basic model information.

### Run model_explorer

```bash
$ ./model_explorer simple_linear.onnx
.
.
.
Model info
----------
  Model handle: 0x7fe8426ce1d8
  Name: model-explorer
  Model version: 1
  Model interface version: 0
  Index: 0
  Number of inputs: 1
    Input[0]: Name: x, Data_type: int32, Shape: static [1], Size: 4
  Number of outputs: 1
    Output[0]: Name: y, Data_type: int32, Shape: static [1], Size: 4
.
.
.
```
