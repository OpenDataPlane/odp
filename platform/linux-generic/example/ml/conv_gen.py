# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2024 Nokia
#

import onnx
from onnx import helper
from onnx import TensorProto

graph = helper.make_graph(
    [  # nodes
        helper.make_node("Conv", ["X", "W"], ["Y"], "Conv Node"),
    ],
    "Test Graph",  # name
    [  # inputs
        helper.make_tensor_value_info('X', TensorProto.FLOAT, [1, 1, 1, 2]),
    ],
    [  # outputs
        helper.make_tensor_value_info('Y', TensorProto.FLOAT, [1, 1, 1, 2]),
    ],
    [  # initializer
        helper.make_tensor('W', TensorProto.FLOAT, [1, 1, 1, 1], [2.0]),
    ],
)

model = helper.make_model(
    graph,
    opset_imports=[helper.make_opsetid("", 14)],
    producer_name='ODP validation tests',
    model_version=1,
    doc_string="output = 2 * input",
    ir_version = 8
)

onnx.save(model, 'conv.onnx')
