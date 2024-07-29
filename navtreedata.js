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
    [ "Deprecated List", "deprecated.html", null ],
    [ "Modules", "modules.html", "modules" ],
    [ "Data Structures", "annotated.html", [
      [ "Data Structures", "annotated.html", "annotated_dup" ],
      [ "Data Fields", "functions.html", [
        [ "All", "functions.html", "functions_dup" ],
        [ "Variables", "functions_vars.html", "functions_vars" ]
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
"api_2spec_2std__types_8h.html",
"arch_2default-linux_2odp_2api_2abi_2version_8h_source.html",
"group__odp__atomic.html#ga048eaef4215c07cb7fd140011fd0ee36",
"group__odp__classification.html#gga7cf6618755c8bc947bd82df214b1ad9ea0b5392e9b6ead3d329041d7bf2337a4d",
"group__odp__cpu.html#ga1eddc2169c7e7d90f194054499a4548b",
"group__odp__crypto.html#gga97ed3811136cd7888625a4973c416982ab0353f472300af96fc0601eca5100534",
"group__odp__initialization.html#ga6d15f0e1718da9477948dedb06a2f01a",
"group__odp__locks.html#ga15e51b78a0c9bd3fb94c669e7d448106",
"group__odp__packet.html#ga02e9829352d32aec8c8904964cddf158",
"group__odp__packet.html#ga881c983f915f15a531a80de8dd08d95d",
"group__odp__packet.html#gga1c1953ca031653b51469128363e55ab8a07f42c299dba340592495aa77abf955a",
"group__odp__packet__io.html#gadbc8d348315921b12e623cc57695f9f2",
"group__odp__queue.html#ga89a3439d3f3be48cac1767cba721edda",
"group__odp__stash.html#ga6f4891eac8b3a7e35119f634b5eda822",
"group__odp__thread.html#gaeae6aec8642773eb81b005bfac8cb152",
"group__odp__traffic__mngr.html#ga1e9b7760d826e51cd9b008681fc44c46",
"ipsec__crypto_2odp__ipsec__stream_8c_source.html",
"structodp__cls__cos__param.html#a7be4913992d0f41c73eb6823958a177c",
"structodp__ipsec__in__param__t.html#a7de98bd0265da777b51d085b6ef6c6cc",
"structodp__ml__model__param__t.html#a04872dfa7151774c73b41a8f3e5d77c6",
"structodp__pmr__param__t.html#a2a00c26ec5488361eb5d81195be5c125",
"structodp__stash__param__t.html#a8908a6c2445d28a865d98ba0e49d78cd",
"structodp__tm__wred__params__t.html#a359fabde4e477c19f2ca7087beefc9ae",
"unionodp__threshold__types__t.html"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';