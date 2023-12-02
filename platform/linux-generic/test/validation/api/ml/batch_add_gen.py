# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2023 Nokia
#

import onnx
from onnx import helper
from onnx import TensorProto

graph = helper.make_graph(
    [  # nodes
        helper.make_node("Add", ["x1", "x2"], ["y"], "Batch Add"),
    ],
    "Batch Add",  # name
    [  # inputs
        helper.make_tensor_value_info('x1', TensorProto.DOUBLE, ["c", 3]),
        helper.make_tensor_value_info('x2', TensorProto.DOUBLE, ["c", 3]),
    ],
    [  # outputs
        helper.make_tensor_value_info('y', TensorProto.DOUBLE, ["c", 3]),
    ]
)

model = helper.make_model(
    graph,
    opset_imports=[helper.make_opsetid("", 14)],
    producer_name='ODP validation tests',
    model_version=1,
    doc_string="y = x1 + x2",
    ir_version = 8
)

onnx.save(model, 'batch_add.onnx')
