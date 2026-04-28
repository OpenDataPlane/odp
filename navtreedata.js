/*
 @licstart  The following is the entire license notice for the JavaScript code in this file.

 The MIT License (MIT)

 Copyright (C) 1997-2020 by Dimitri van Heesch

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 and associated documentation files (the "Software"), to deal in the Software without restriction,
 including without limitation the rights to use, copy, modify, merge, publish, distribute,
 sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or
 substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 @licend  The above is the entire license notice for the JavaScript code in this file
*/
var NAVTREE =
[
  [ "API Reference Manual", "index.html", [
    [ "Introduction", "index.html#sec_1", null ],
    [ "Contact Details", "index.html#contact", null ],
    [ "API Developer Guidelines", "api_guide_lines.html", [
      [ "Introduction", "api_guide_lines.html#introduction", null ],
      [ "Functional Definition", "api_guide_lines.html#functional", [
        [ "Naming Conventions", "api_guide_lines.html#naming", null ],
        [ "Data Types and Use of typedef", "api_guide_lines.html#data_types", null ],
        [ "Parameter Structure and Validation", "api_guide_lines.html#parameters", null ],
        [ "Function Names", "api_guide_lines.html#function_name", null ],
        [ "Getting information", "api_guide_lines.html#getters", [
          [ "Is / Has", "api_guide_lines.html#is_has", null ],
          [ "Get", "api_guide_lines.html#get", null ]
        ] ],
        [ "Converter Functions", "api_guide_lines.html#converter", null ],
        [ "Function Calls", "api_guide_lines.html#function_calls", null ],
        [ "Use of errno", "api_guide_lines.html#errno", null ],
        [ "Boolean", "api_guide_lines.html#boolean", null ],
        [ "Success and Failure", "api_guide_lines.html#success", null ],
        [ "Internal APIs", "api_guide_lines.html#odp_internal", null ],
        [ "Declaring variables", "api_guide_lines.html#variables", null ]
      ] ],
      [ "Implementation Considerations", "api_guide_lines.html#implementation", [
        [ "Application View vs. Implementation View", "api_guide_lines.html#application_view", null ],
        [ "Essential functions vs. Extensions", "api_guide_lines.html#essential_functions", null ],
        [ "ODP DEPRECATE", "api_guide_lines.html#odp_deprecate", null ]
      ] ],
      [ "Default behaviours", "api_guide_lines.html#defaults", null ]
    ] ],
    [ "API Principles", "api_principles.html", null ],
    [ "Contributing Guidelines", "contributing.html", null ],
    [ "Release Management", "release.html", [
      [ "API Numbering", "release.html#api_numbering", [
        [ "Generation", "release.html#generation", null ],
        [ "Major", "release.html#major", null ],
        [ "Minor", "release.html#minor", null ]
      ] ],
      [ "Implementation String", "release.html#implementation_string", null ]
    ] ],
    [ "Modules", "modules.html", "modules" ],
    [ "Data Structures", "annotated.html", [
      [ "Data Structures", "annotated.html", "annotated_dup" ],
      [ "Data Fields", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Variables", "functions_vars.html", "functions_vars" ],
        [ "Enumerator", "functions_eval.html", null ]
      ] ]
    ] ],
    [ "Files", "files.html", [
      [ "File List", "files.html", "files_dup" ],
      [ "Globals", "globals.html", [
        [ "All", "globals.html", "globals_dup" ],
        [ "Functions", "globals_func.html", "globals_func" ],
        [ "Typedefs", "globals_type.html", "globals_type" ],
        [ "Enumerations", "globals_enum.html", null ],
        [ "Enumerator", "globals_eval.html", "globals_eval" ],
        [ "Macros", "globals_defs.html", null ]
      ] ]
    ] ],
    [ "Examples", "examples.html", "examples" ]
  ] ]
];

var NAVTREEINDEX =
[
"annotated.html",
"api_2spec_2spinlock_8h.html",
"arch_2default-linux_2odp_2api_2abi_2spinlock_8h_source.html",
"functions_vars_o.html",
"group__odp__classification.html#ga3ef005a4db2d03311bca75b00e18cda9",
"group__odp__compression.html#gaa3d3c0e31a9d442538f27d1e4809a01d",
"group__odp__crypto.html#gga3c943d596daa203f2c71263ad4386ff0ac8c68b6ba7437f58342798b8b9321d49",
"group__odp__event.html#ga04bd6c5f6c2630807e90e63edf7ad9b2",
"group__odp__ipsec.html#gaac6b2c4bdc5102d934f6c4948a16983e",
"group__odp__ml.html#ga6c9a31ff73e458449e86b55fc8337230",
"group__odp__packet.html#ga34cecc1ff01ab01bbcbd18dd8ef535fb",
"group__odp__packet.html#gac249f19ed0caf5b7315f6ee8d02cd8ef",
"group__odp__packet__io.html#ga4aeba34d1fdced940628f8d791388796",
"group__odp__pool.html#ga019db2e55a3f186edf09f1d0c6576d90",
"group__odp__scheduler.html#ga2ba135fc660e1c050aa25ec6744ec584",
"group__odp__std.html#gace4553e43c2008a72c315f6d4138f253",
"group__odp__timer.html#ga0fee646104698b68bd01f60d02537538",
"group__odp__traffic__mngr.html#ga747206e3585f3b3f233704f8a789bf0a",
"odp__stash__perf_8c_source.html",
"structodp__cls__queue__stats__t.html#a2c57a3f66755e66c15228b2423fc1120",
"structodp__ipsec__config__t.html#ae2b53220f4f03159efd896407ad6c893",
"structodp__ml__data__format__t.html",
"structodp__pktio__stats__capability__t.html#a5ba54d51c9294a0dd78b204a624f301a",
"structodp__schedule__capability__t.html#af5a0012afd72305d3cf73949208706b4",
"structodp__tm__level__capabilities__t.html#a9d894d48606f28f991e815f0e83024a5",
"unionodp__crypto__auth__algos__t.html#ad5e594132f40b6b9425d557892b20bfb"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';