var group__odp__compression =
[
    [ "odp_comp_hash_algos_t", "unionodp__comp__hash__algos__t.html", [
      [ "none", "unionodp__comp__hash__algos__t.html#aff612dcba4edd967d3e6fdb8c29a053d", null ],
      [ "sha1", "unionodp__comp__hash__algos__t.html#a0b999048cfbd6d3a4c344944e4b85d2e", null ],
      [ "sha256", "unionodp__comp__hash__algos__t.html#aa77c90433073b63d976de6ae91c29c4d", null ],
      [ "bit", "unionodp__comp__hash__algos__t.html#aeffe30c6de3a08881a8860ee63f43324", null ],
      [ "all_bits", "unionodp__comp__hash__algos__t.html#afb2abe0c353fddb3f067b961217d7d4c", null ]
    ] ],
    [ "odp_comp_algos_t", "unionodp__comp__algos__t.html", [
      [ "null", "unionodp__comp__algos__t.html#a185e750b42df16486dbf5467e42c89e5", null ],
      [ "deflate", "unionodp__comp__algos__t.html#a9b3c0f286a944dc9cf713dff2adad628", null ],
      [ "zlib", "unionodp__comp__algos__t.html#a8b7d9cbd379330aeb1e46d5f962a4b9f", null ],
      [ "lzs", "unionodp__comp__algos__t.html#a696de87672990276be7d6d35aeb293ea", null ],
      [ "bit", "unionodp__comp__algos__t.html#ad6d58de808462115005edc8a40c9b216", null ],
      [ "all_bits", "unionodp__comp__algos__t.html#a8eaa821c8aae8b55f5542b4e406b59ec", null ]
    ] ],
    [ "odp_comp_capability_t", "structodp__comp__capability__t.html", [
      [ "max_sessions", "structodp__comp__capability__t.html#a55ee0de1d84f4d8ddcaec2ce692b1fa1", null ],
      [ "comp_algos", "structodp__comp__capability__t.html#aa81f5bd48eee1529c0099944653dfa47", null ],
      [ "hash_algos", "structodp__comp__capability__t.html#a8566a2817edda1a41ae923b0626a9316", null ],
      [ "sync", "structodp__comp__capability__t.html#a2a8f12082475aa7ba1c12d77d876b7ac", null ],
      [ "async", "structodp__comp__capability__t.html#a7f07b6eb45b0aede8f1aab50101bef11", null ]
    ] ],
    [ "odp_comp_hash_alg_capability_t", "structodp__comp__hash__alg__capability__t.html", [
      [ "digest_len", "structodp__comp__hash__alg__capability__t.html#af1d848dbf6ff3c39924d0e2247010dbe", null ]
    ] ],
    [ "odp_comp_alg_capability_t", "structodp__comp__alg__capability__t.html", [
      [ "max_level", "structodp__comp__alg__capability__t.html#a9fabffa77ed51f93104db72edf0a6fb2", null ],
      [ "hash_algo", "structodp__comp__alg__capability__t.html#a1972e97b9d7039142b0a786aecc45839", null ],
      [ "compression_ratio", "structodp__comp__alg__capability__t.html#ae80418fbaf2e3d6e7b8b2c259ae32a64", null ]
    ] ],
    [ "odp_comp_deflate_param", "structodp__comp__deflate__param.html", [
      [ "comp_level", "structodp__comp__deflate__param.html#ac28db75d3530c75a5daa305e7d713a0d", null ],
      [ "huffman_code", "structodp__comp__deflate__param.html#a4f98572231c607098362e9bd8d3acd75", null ]
    ] ],
    [ "odp_comp_alg_param_t", "unionodp__comp__alg__param__t.html", [
      [ "deflate", "unionodp__comp__alg__param__t.html#a0147e268612cfb786b5b97dc50149640", null ],
      [ "zlib", "unionodp__comp__alg__param__t.html#a5f8adfe946b315e3d7bf17d601f96273", null ]
    ] ],
    [ "odp_comp_session_param_t", "structodp__comp__session__param__t.html", [
      [ "op", "structodp__comp__session__param__t.html#a2d4e420b29b41b2d6f4c3b3bdb608ecc", null ],
      [ "mode", "structodp__comp__session__param__t.html#a7f80786acbb01a1208a4ec9adaf9659a", null ],
      [ "comp_algo", "structodp__comp__session__param__t.html#aeb5dc062aa2317b1e40d902039939785", null ],
      [ "hash_algo", "structodp__comp__session__param__t.html#a91e1047e76e8849f784e0eb86de71020", null ],
      [ "alg_param", "structodp__comp__session__param__t.html#a038ca883d7dc3f9e39a44bcad10a02df", null ],
      [ "packet_order", "structodp__comp__session__param__t.html#af18fa86f8cf844db5e4b0bf40ee87868", null ],
      [ "compl_queue", "structodp__comp__session__param__t.html#a847acec8b1944ccf2abfc57c7fff6ee6", null ]
    ] ],
    [ "odp_comp_packet_result_t", "structodp__comp__packet__result__t.html", [
      [ "status", "structodp__comp__packet__result__t.html#af212e4d63cc05fa9bd44cbe034aeab25", null ],
      [ "pkt_in", "structodp__comp__packet__result__t.html#a06d13cce67b35dd4f9f1f19ea174b358", null ],
      [ "output_data_range", "structodp__comp__packet__result__t.html#acc4ffad88ea5c18435f822dd2c3544cb", null ]
    ] ],
    [ "odp_comp_packet_op_param_t", "structodp__comp__packet__op__param__t.html", [
      [ "session", "structodp__comp__packet__op__param__t.html#a9aa373ab6ba5918cedd7531f7e79edc6", null ],
      [ "in_data_range", "structodp__comp__packet__op__param__t.html#a73c0fadafc142033f6430b124c73fb82", null ],
      [ "out_data_range", "structodp__comp__packet__op__param__t.html#a8f0e922b56b24d7629eaeac3b513074f", null ]
    ] ],
    [ "ODP_COMP_SESSION_INVALID", "group__odp__compression.html#ga285a1db95fcf42e66f36054d61142075", null ],
    [ "odp_comp_session_t", "group__odp__compression.html#ga084a9a08719dea52b69bc3c25227eca9", null ],
    [ "odp_comp_hash_algos_t", "group__odp__compression.html#gabb58ff9ac3fce1cf3ce748b96ced8803", null ],
    [ "odp_comp_algos_t", "group__odp__compression.html#ga02fa4e95e2107bd00aec18082b2937a5", null ],
    [ "odp_comp_capability_t", "group__odp__compression.html#ga80fca305e4ebbe165c05d30dc19b9168", null ],
    [ "odp_comp_hash_alg_capability_t", "group__odp__compression.html#ga587751b67a4b9c1aa8396c5aa9589901", null ],
    [ "odp_comp_alg_capability_t", "group__odp__compression.html#ga001ab5cd672e9d02ff0713cc013e6772", null ],
    [ "odp_comp_huffman_code_t", "group__odp__compression.html#ga30c1906a5a14ccddea1c58dd31649b1d", null ],
    [ "odp_comp_deflate_param_t", "group__odp__compression.html#gae1cf60859b25484b2877d87b1d96974b", null ],
    [ "odp_comp_alg_param_t", "group__odp__compression.html#gad0795f3b06e7e04601ed5a1fa3b45e36", null ],
    [ "odp_comp_session_param_t", "group__odp__compression.html#ga811e2c85ac2f9f2b91c45c1d219e6bcf", null ],
    [ "odp_comp_packet_result_t", "group__odp__compression.html#ga1edf555bef4c5e3cf3694facd580d3a8", null ],
    [ "odp_comp_packet_op_param_t", "group__odp__compression.html#ga48f55f5af19406f12b74516ca53d3dba", null ],
    [ "odp_comp_op_mode_t", "group__odp__compression.html#ga82ccdf3e822eb1bd5303a1c4e62143b4", [
      [ "ODP_COMP_OP_MODE_SYNC", "group__odp__compression.html#gga82ccdf3e822eb1bd5303a1c4e62143b4abf1b03eb649380abb689ae1bc749b603", null ],
      [ "ODP_COMP_OP_MODE_ASYNC", "group__odp__compression.html#gga82ccdf3e822eb1bd5303a1c4e62143b4a2b53ed15d142d0ef67c5c28de0fe56ea", null ]
    ] ],
    [ "odp_comp_op_t", "group__odp__compression.html#gaeeb6356e03c9492c0a35635e4c02f117", [
      [ "ODP_COMP_OP_COMPRESS", "group__odp__compression.html#ggaeeb6356e03c9492c0a35635e4c02f117a25189d5dcae1178b72582989f4ace958", null ],
      [ "ODP_COMP_OP_DECOMPRESS", "group__odp__compression.html#ggaeeb6356e03c9492c0a35635e4c02f117ae5f5da2ba372adcbf7aac0cc30dee430", null ]
    ] ],
    [ "odp_comp_hash_alg_t", "group__odp__compression.html#ga16a247ebeb856873a13ebaec2a048282", [
      [ "ODP_COMP_HASH_ALG_NONE", "group__odp__compression.html#gga16a247ebeb856873a13ebaec2a048282a83dd7039032ffa592883f3b4f7cbdfe5", null ],
      [ "ODP_COMP_HASH_ALG_SHA1", "group__odp__compression.html#gga16a247ebeb856873a13ebaec2a048282afa2c022dcf21a5422ad4b0e4ce58440f", null ],
      [ "ODP_COMP_HASH_ALG_SHA256", "group__odp__compression.html#gga16a247ebeb856873a13ebaec2a048282a524d85c0d0aec3f33e450af413113686", null ]
    ] ],
    [ "odp_comp_alg_t", "group__odp__compression.html#gaa48820605aab44a1614c8cec83a17c4c", [
      [ "ODP_COMP_ALG_NULL", "group__odp__compression.html#ggaa48820605aab44a1614c8cec83a17c4ca43f36a87fa227ac0f1f49e764c4a5be2", null ],
      [ "ODP_COMP_ALG_DEFLATE", "group__odp__compression.html#ggaa48820605aab44a1614c8cec83a17c4ca64c4fdc8fa2d776bb17f1d7d6e52be77", null ],
      [ "ODP_COMP_ALG_ZLIB", "group__odp__compression.html#ggaa48820605aab44a1614c8cec83a17c4cac570a4d4d9f0c87534b1dc36227d7a61", null ],
      [ "ODP_COMP_ALG_LZS", "group__odp__compression.html#ggaa48820605aab44a1614c8cec83a17c4caf2772e92f1b7f5a66d825c0285cc9152", null ]
    ] ],
    [ "odp_comp_status_t", "group__odp__compression.html#ga8ed641fd8d5f6362d5bbcbdb75d28f71", [
      [ "ODP_COMP_STATUS_SUCCESS", "group__odp__compression.html#gga8ed641fd8d5f6362d5bbcbdb75d28f71aa9d733b932192b5a9f1dfb01a07eebda", null ],
      [ "ODP_COMP_STATUS_OUT_OF_SPACE_TERM", "group__odp__compression.html#gga8ed641fd8d5f6362d5bbcbdb75d28f71a3b5ea31082e21c32bebfb21fc4b622f7", null ],
      [ "ODP_COMP_STATUS_FAILURE", "group__odp__compression.html#gga8ed641fd8d5f6362d5bbcbdb75d28f71ad011e6f28703208a3062b87a60e5d71a", null ]
    ] ],
    [ "odp_comp_huffman_code", "group__odp__compression.html#ga40431e6d8b6422c273eeec9ce55b1724", [
      [ "ODP_COMP_HUFFMAN_FIXED", "group__odp__compression.html#gga40431e6d8b6422c273eeec9ce55b1724a3d9fc92db9423aee0ae1ba0c6f26d3fa", null ],
      [ "ODP_COMP_HUFFMAN_DYNAMIC", "group__odp__compression.html#gga40431e6d8b6422c273eeec9ce55b1724a310407a1bf01922b13f0dc121543289c", null ],
      [ "ODP_COMP_HUFFMAN_DEFAULT", "group__odp__compression.html#gga40431e6d8b6422c273eeec9ce55b1724a55ab6e63adfc11df075def4521a8d74b", null ]
    ] ],
    [ "odp_comp_capability", "group__odp__compression.html#ga57f80bfca03138f9d53fb282cdd10744", null ],
    [ "odp_comp_alg_capability", "group__odp__compression.html#ga8091ad40e4e7647573f1f779242c3e39", null ],
    [ "odp_comp_hash_alg_capability", "group__odp__compression.html#gab6a21fa1b861b84752f3ab536c1599a6", null ],
    [ "odp_comp_session_param_init", "group__odp__compression.html#gaa3d3c0e31a9d442538f27d1e4809a01d", null ],
    [ "odp_comp_session_create", "group__odp__compression.html#ga0e9bc8f069216db93b83e8d67432c256", null ],
    [ "odp_comp_session_destroy", "group__odp__compression.html#ga036a75d3d5ac480465c464fa4dce26de", null ],
    [ "odp_comp_op", "group__odp__compression.html#gae3106c185ad6f9ea8e22b8f9da74129b", null ],
    [ "odp_comp_op_enq", "group__odp__compression.html#ga4737acd0072f3313f269e3142ecfabdf", null ],
    [ "odp_comp_result", "group__odp__compression.html#ga414537713ad791c143310a8e07615f27", null ],
    [ "odp_comp_packet_from_event", "group__odp__compression.html#ga30c2ae6e9c2958482edea4b83c47c810", null ],
    [ "odp_comp_packet_to_event", "group__odp__compression.html#gaa3991629c7c7aefeb55e96f323a8ae65", null ],
    [ "odp_comp_session_to_u64", "group__odp__compression.html#ga27a08db102f1cdb9ba7b793966551263", null ]
];