var group__odp__timer =
[
    [ "odp_timer_res_capability_t", "structodp__timer__res__capability__t.html", [
      [ "res_ns", "structodp__timer__res__capability__t.html#af1eb01598a9d584c800a16d247cf93e4", null ],
      [ "res_hz", "structodp__timer__res__capability__t.html#a246a16330982521b9e942910577bf9e8", null ],
      [ "min_tmo", "structodp__timer__res__capability__t.html#adcb9e123e1c721ddf6d7400ba845d506", null ],
      [ "max_tmo", "structodp__timer__res__capability__t.html#a93a95f867b80c8bfddd0b69ad922589c", null ]
    ] ],
    [ "odp_timer_periodic_capability_t", "structodp__timer__periodic__capability__t.html", [
      [ "base_freq_hz", "structodp__timer__periodic__capability__t.html#a9cd269188250e8e0aaa22aafba9d52e1", null ],
      [ "max_multiplier", "structodp__timer__periodic__capability__t.html#ad4e5616a157ace57ded853ee16271254", null ],
      [ "res_ns", "structodp__timer__periodic__capability__t.html#aa28b6af956546b02bdf03731d4e5586b", null ]
    ] ],
    [ "odp_timer_capability_t", "structodp__timer__capability__t.html", [
      [ "max_pools_combined", "structodp__timer__capability__t.html#a47ff49026c311c13d8d90a2c5cc03d8c", null ],
      [ "max_pools", "structodp__timer__capability__t.html#a58725f2fc93aa22c3d0558c206d22a75", null ],
      [ "max_timers", "structodp__timer__capability__t.html#a32b32547137ee30f55c073ad858c0d0a", null ],
      [ "highest_res_ns", "structodp__timer__capability__t.html#af0616eb9ff6667d142bb0e6febef7135", null ],
      [ "max_res", "structodp__timer__capability__t.html#a88b0a6aba07f696cd4b5d012ae6fc85c", null ],
      [ "max_tmo", "structodp__timer__capability__t.html#a6a4520267ee52e75ddf0be1fbc418bb4", null ],
      [ "queue_type_sched", "structodp__timer__capability__t.html#af53971e70cb459a10204571a468ed939", null ],
      [ "queue_type_plain", "structodp__timer__capability__t.html#aaa1285fa6a628457d0b316664ea1bfc7", null ],
      [ "min_base_freq_hz", "structodp__timer__capability__t.html#a11521af16173bfe7ae83ea217a9e72ef", null ],
      [ "max_base_freq_hz", "structodp__timer__capability__t.html#a886f075428980a2a20560773e0294fb1", null ],
      [ "periodic", "structodp__timer__capability__t.html#a7976f42f69085ab42b2c0b40d7ae5bf0", null ]
    ] ],
    [ "odp_timer_pool_param_t", "structodp__timer__pool__param__t.html", [
      [ "timer_type", "structodp__timer__pool__param__t.html#a5098c7331e3be5ae4917497f7f22fc95", null ],
      [ "clk_src", "structodp__timer__pool__param__t.html#af491eee5937cbb0b8e18a85a9712c07c", null ],
      [ "exp_mode", "structodp__timer__pool__param__t.html#ae4555c2f75abeaa32244fb8204a3c5c4", null ],
      [ "res_ns", "structodp__timer__pool__param__t.html#a0c9d28e284d142c3fe6ee5f8cc66171e", null ],
      [ "res_hz", "structodp__timer__pool__param__t.html#a28ac8ecc44799f4510a8d182158ee0bc", null ],
      [ "min_tmo", "structodp__timer__pool__param__t.html#a8c358d197ea76dc7295025c23159e890", null ],
      [ "max_tmo", "structodp__timer__pool__param__t.html#af54f6e42c3f0fc4e2514c2d0df3023c2", null ],
      [ "base_freq_hz", "structodp__timer__pool__param__t.html#a789cbb379c8987f75c71d32c1df5e63a", null ],
      [ "max_multiplier", "structodp__timer__pool__param__t.html#a5fca5e7fd6f46dab86a532cc9220010c", null ],
      [ "periodic", "structodp__timer__pool__param__t.html#a4513759753a622da48fa300ea50e0b03", null ],
      [ "num_timers", "structodp__timer__pool__param__t.html#abe013f91043de4d7fa0003bce6701a3f", null ],
      [ "priv", "structodp__timer__pool__param__t.html#a8b9276c132f7b79cf51787167febbfea", null ]
    ] ],
    [ "odp_timer_start_t", "structodp__timer__start__t.html", [
      [ "tick_type", "structodp__timer__start__t.html#adff5d0b4bfbce079f01ec86642a387fe", null ],
      [ "tick", "structodp__timer__start__t.html#a00d0c90df7accbbed0f22273365b6c56", null ],
      [ "tmo_ev", "structodp__timer__start__t.html#a8c7915d1a2cfa0bb13f8cbf280ee7a97", null ]
    ] ],
    [ "odp_timer_periodic_start_t", "structodp__timer__periodic__start__t.html", [
      [ "first_tick", "structodp__timer__periodic__start__t.html#af1e4cbbbff88e773fccc75d89568406d", null ],
      [ "freq_multiplier", "structodp__timer__periodic__start__t.html#a37ffb16cb284b5363bde6d6199b665d8", null ],
      [ "tmo_ev", "structodp__timer__periodic__start__t.html#a08a057c61c37699ca3806319d84ccae5", null ]
    ] ],
    [ "odp_timer_tick_info_t", "structodp__timer__tick__info__t.html", [
      [ "freq", "structodp__timer__tick__info__t.html#a6552b1bfd453866c1a1114dfddb83756", null ],
      [ "nsec", "structodp__timer__tick__info__t.html#a88bfd1e6162a6939173d046f3d1ca655", null ],
      [ "clk_cycle", "structodp__timer__tick__info__t.html#a42464f9579c9751c7f42747ec2f4be03", null ]
    ] ],
    [ "odp_timer_pool_info_t", "structodp__timer__pool__info__t.html", [
      [ "param", "structodp__timer__pool__info__t.html#ac09e4f912ae8074a5c89bb854d0cdb47", null ],
      [ "cur_timers", "structodp__timer__pool__info__t.html#aafd7f85e65d376b387ea3c56499f29f6", null ],
      [ "hwm_timers", "structodp__timer__pool__info__t.html#a7f960a2cfe6d8671acf5f86c2e18cad8", null ],
      [ "name", "structodp__timer__pool__info__t.html#ae12ce6d1db5ced5bb9bf20d836383028", null ],
      [ "tick_info", "structodp__timer__pool__info__t.html#a00acb5bcff429dafdf997a0fb93c386d", null ]
    ] ],
    [ "ODP_TIMER_POOL_INVALID", "group__odp__timer.html#ga4ad1abeaffbe94d9bbc66a0d8bab76c3", null ],
    [ "ODP_TIMER_POOL_NAME_LEN", "group__odp__timer.html#ga283ef3192cef91f706ef0f87cdd27af3", null ],
    [ "ODP_TIMER_INVALID", "group__odp__timer.html#gaea51c621bb26b7a8bdab46d8a08f247a", null ],
    [ "ODP_TIMEOUT_INVALID", "group__odp__timer.html#gac72c1c2f923ee0d53b0a7d4109da34a5", null ],
    [ "ODP_CLOCK_DEFAULT", "group__odp__timer.html#gadb0936032a6640db772dd99cf4eb9159", null ],
    [ "odp_timer_pool_t", "group__odp__timer.html#ga9e733079ef99b6f0d3807fd57f29b267", null ],
    [ "odp_timer_t", "group__odp__timer.html#ga487bfb01cfce31d26242acf5dc671aa5", null ],
    [ "odp_timeout_t", "group__odp__timer.html#gafd2feebd15c4f907577d1a89c36acddb", null ],
    [ "odp_timer_start_t", "group__odp__timer.html#ga83c7b2feb781ea7474508d407f9ae87e", null ],
    [ "odp_timer_periodic_start_t", "group__odp__timer.html#ga65a87a282c9bd13c5e814052106ea9e8", null ],
    [ "odp_timer_set_t", "group__odp__timer.html#gab9b1e7712d0871680173097617b06a6f", null ],
    [ "odp_timer_tick_info_t", "group__odp__timer.html#gaeff40ed377d1db1b729ee7dabd8d6ecd", null ],
    [ "odp_timer_type_t", "group__odp__timer.html#gac7f82b0c232f44c4079a885e9abaf39a", [
      [ "ODP_TIMER_TYPE_SINGLE", "group__odp__timer.html#ggac7f82b0c232f44c4079a885e9abaf39aab0ae61fce5d071dedb8885cdd407fd97", null ],
      [ "ODP_TIMER_TYPE_PERIODIC", "group__odp__timer.html#ggac7f82b0c232f44c4079a885e9abaf39aaafb98c807ea1b44b05ef8dd3b827b69f", null ]
    ] ],
    [ "odp_timer_clk_src_t", "group__odp__timer.html#ga8fe485cf54a752259326c68e425b7e3e", [
      [ "ODP_CLOCK_SRC_0", "group__odp__timer.html#gga8fe485cf54a752259326c68e425b7e3eadb9068ee59e694f548c9b8cfbfe3db56", null ],
      [ "ODP_CLOCK_SRC_1", "group__odp__timer.html#gga8fe485cf54a752259326c68e425b7e3ea013c7028cca0a2314a4d52953f323972", null ],
      [ "ODP_CLOCK_SRC_2", "group__odp__timer.html#gga8fe485cf54a752259326c68e425b7e3ea8380e97ed52a763b5e9863b72f746c3a", null ],
      [ "ODP_CLOCK_SRC_3", "group__odp__timer.html#gga8fe485cf54a752259326c68e425b7e3ea790c4ee56b9e89465ccbb9fe05e24c01", null ],
      [ "ODP_CLOCK_SRC_4", "group__odp__timer.html#gga8fe485cf54a752259326c68e425b7e3eaa8e3978f5959abcc40fedd33c2f6f8ff", null ],
      [ "ODP_CLOCK_SRC_5", "group__odp__timer.html#gga8fe485cf54a752259326c68e425b7e3eaa485ee9be21a79effada2fa7b14b7aeb", null ],
      [ "ODP_CLOCK_NUM_SRC", "group__odp__timer.html#gga8fe485cf54a752259326c68e425b7e3ea946f4788fe4ff4f18c5c0d8f18c7e2ab", null ]
    ] ],
    [ "odp_timer_exp_mode_t", "group__odp__timer.html#gafb50e0979b28e791d134707eabde74f4", [
      [ "ODP_TIMER_EXP_AFTER", "group__odp__timer.html#ggafb50e0979b28e791d134707eabde74f4ada3767f9f63273b9f2f5e1d855f6f1cf", null ],
      [ "ODP_TIMER_EXP_RELAXED", "group__odp__timer.html#ggafb50e0979b28e791d134707eabde74f4a9ab08f284c8099346a475cce855b9b34", null ]
    ] ],
    [ "odp_timer_tick_type_t", "group__odp__timer.html#gafe9103bdca21be1c7f14c83fedbf9b29", [
      [ "ODP_TIMER_TICK_REL", "group__odp__timer.html#ggafe9103bdca21be1c7f14c83fedbf9b29a46ef02de17dc80bca0684f0f8087dd57", null ],
      [ "ODP_TIMER_TICK_ABS", "group__odp__timer.html#ggafe9103bdca21be1c7f14c83fedbf9b29ac1978457853ee766f0c10bf59ad9cd82", null ]
    ] ],
    [ "odp_timer_retval_t", "group__odp__timer.html#gabd0fe407d8c3d7370b2bff479ae1d78c", [
      [ "ODP_TIMER_SUCCESS", "group__odp__timer.html#ggabd0fe407d8c3d7370b2bff479ae1d78ca6cf6bb923bdf13cede58a481443be93c", null ],
      [ "ODP_TIMER_TOO_NEAR", "group__odp__timer.html#ggabd0fe407d8c3d7370b2bff479ae1d78ca960770553750528ffd90285f9729c99f", null ],
      [ "ODP_TIMER_TOO_FAR", "group__odp__timer.html#ggabd0fe407d8c3d7370b2bff479ae1d78ca9826e74a06aae31168ea7aad4c944b8d", null ],
      [ "ODP_TIMER_FAIL", "group__odp__timer.html#ggabd0fe407d8c3d7370b2bff479ae1d78cafcabd0f01c3d19d8c9063ccd861edd6e", null ]
    ] ],
    [ "odp_timer_capability", "group__odp__timer.html#ga7064c7d4e9f014ffd322222178d208b3", null ],
    [ "odp_timer_res_capability", "group__odp__timer.html#gabe0347bf41e1fd2faff5a213fef32b24", null ],
    [ "odp_timer_periodic_capability", "group__odp__timer.html#ga4bf3eb01eed3756e4e41fc38c4aef0fd", null ],
    [ "odp_timer_pool_param_init", "group__odp__timer.html#gaf680f0ddeb5270d8a8947e2445b22dff", null ],
    [ "odp_timer_pool_create", "group__odp__timer.html#ga5119deda378994a468934aef41993965", null ],
    [ "odp_timer_pool_start", "group__odp__timer.html#ga1c28fd4fb9830d754aa00563448e82ec", null ],
    [ "odp_timer_pool_start_multi", "group__odp__timer.html#ga0d106b4ca2047a5a5dda17ce6b6bc0b1", null ],
    [ "odp_timer_pool_destroy", "group__odp__timer.html#gafb56c5aff06be798de32d878266febc0", null ],
    [ "odp_timer_tick_to_ns", "group__odp__timer.html#ga0d06e6c0203ee0892f4e2d823682aa59", null ],
    [ "odp_timer_ns_to_tick", "group__odp__timer.html#ga7fb23a28aa1db3c919aa49c90b2316fb", null ],
    [ "odp_timer_current_tick", "group__odp__timer.html#ga680573fd461db24d4e66540b37deea43", null ],
    [ "odp_timer_sample_ticks", "group__odp__timer.html#ga5c7f5a2f86d121859359d5f1d7fe258d", null ],
    [ "odp_timer_pool_info", "group__odp__timer.html#gacf39525bc4f8dd2d61ad4e963c931259", null ],
    [ "odp_timer_alloc", "group__odp__timer.html#gad3e1c9b326fe7ec85b635d6f02998a86", null ],
    [ "odp_timer_free", "group__odp__timer.html#ga373923bac02ccf5db59a1fe19c2b3220", null ],
    [ "odp_timer_start", "group__odp__timer.html#gaa31f657dcc4d9e31e379b4f07ff9f83a", null ],
    [ "odp_timer_restart", "group__odp__timer.html#ga447bdef8a57404cc1d594d31c5aa153f", null ],
    [ "odp_timer_periodic_start", "group__odp__timer.html#ga46b7f660a3a08c61437176a3cbf6c048", null ],
    [ "odp_timer_periodic_ack", "group__odp__timer.html#ga81343bf34b3a1573ec289450d5724dab", null ],
    [ "odp_timer_periodic_cancel", "group__odp__timer.html#gac1ae6a034d26535034293879401765c8", null ],
    [ "odp_timer_cancel", "group__odp__timer.html#ga6196cbe6e24df32c3ff66b0e4da57b87", null ],
    [ "odp_timeout_from_event", "group__odp__timer.html#ga47e481181fbc79039f51f9c306257667", null ],
    [ "odp_timeout_from_event_multi", "group__odp__timer.html#gaa662d5d6f4c27d876198f7f22c5ff151", null ],
    [ "odp_timeout_to_event", "group__odp__timer.html#gac65e47ba9fdfd9ea73cb799e8e957d21", null ],
    [ "odp_timeout_fresh", "group__odp__timer.html#gac14be427018b98cbbd1aa3e76fd57e62", null ],
    [ "odp_timeout_timer", "group__odp__timer.html#ga5a6bd9215cd3fb97a41f0440406b91b4", null ],
    [ "odp_timeout_tick", "group__odp__timer.html#ga233f553eb0ba584d3be09431367fad27", null ],
    [ "odp_timeout_user_ptr", "group__odp__timer.html#gaff83af8aaeca807c37862650a3493005", null ],
    [ "odp_timeout_user_area", "group__odp__timer.html#ga78e69ab0fc2a382e9739ea4d09c22ba5", null ],
    [ "odp_timeout_alloc", "group__odp__timer.html#ga1d1006d0da428f8afd5527b673f777a9", null ],
    [ "odp_timeout_alloc_multi", "group__odp__timer.html#gacfc3049fb890627d73f12e3d4ffc7491", null ],
    [ "odp_timeout_free", "group__odp__timer.html#ga032c54e1a8bc2811e3fb4890ceebe912", null ],
    [ "odp_timeout_free_multi", "group__odp__timer.html#gae60cad8d11f9840ecc8ed13c8ded3b9a", null ],
    [ "odp_timer_pool_print", "group__odp__timer.html#ga12e67bee08508451f316a1c4cc6e4b17", null ],
    [ "odp_timer_print", "group__odp__timer.html#ga19a51f3cc3ca9077b0c52378517131c0", null ],
    [ "odp_timeout_print", "group__odp__timer.html#gac46637619571407548696cfad34f7f84", null ],
    [ "odp_timer_pool_to_u64", "group__odp__timer.html#gadd06a15aa89623d13c0278af36632de9", null ],
    [ "odp_timer_to_u64", "group__odp__timer.html#gaebafe4258e44d3b7ba5d110669f0d65a", null ],
    [ "odp_timeout_to_u64", "group__odp__timer.html#ga872113d48fa0aa506c3cefca6b0b3dcb", null ]
];