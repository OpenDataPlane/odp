# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Nokia
#

import onnx
from onnx import helper
from onnx import TensorProto

weight = helper.make_tensor(name='w', data_type=TensorProto.INT32, dims=[1], vals=[3])
w = helper.make_node('Constant', inputs=[], outputs=['w'], name='weight', value=weight)

bias = helper.make_tensor(name='b', data_type=TensorProto.INT32, dims=[1], vals=[4])
b = helper.make_node('Constant', inputs=[], outputs=['b'], name='bias', value=bias)

# The functional nodes:
mul = helper.make_node('Mul', inputs=['x', 'w'], outputs=['wx'], name='Mul')
add = helper.make_node('Add', inputs=['wx', 'b'], outputs=['y'], name='Add')

# Create the graph
g = helper.make_graph([w, mul, b, add], 'linear',
    [helper.make_tensor_value_info('x', TensorProto.INT32, [1])],
    [helper.make_tensor_value_info('y', TensorProto.INT32, [1])]
)

model = helper.make_model(
    producer_name='ODP validation tests',
    model_version=1,
    doc_string="y = 3x + 4",
    graph=g,
    opset_imports=[helper.make_opsetid("", 13)]
)

# Save the model
onnx.save(model, 'simple_linear.onnx')
