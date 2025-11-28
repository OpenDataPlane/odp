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
"functions_vars_r.html",
"group__odp__classification.html#ga42d053b52bfd01f2d75dc99ae5fead18",
"group__odp__compression.html#gaa48820605aab44a1614c8cec83a17c4c",
"group__odp__crypto.html#gga3c943d596daa203f2c71263ad4386ff0ae5930ea5af5b5999e2c36f403985b248",
"group__odp__event.html#ga1622f73356c325f625db747cb3badf8d",
"group__odp__ipsec.html#gab81f2a38a01fc4ac01fb59dc73351a43",
"group__odp__ml.html#ga7c583b4c886717eb284fac2309ad88a5",
"group__odp__packet.html#ga3628c01444ad1f0717c6db5861fab1dc",
"group__odp__packet.html#gac429a8ec2d57e17022174155a18c2728",
"group__odp__packet__io.html#ga506ab30c6737e9fbd815f0044396893b",
"group__odp__pool.html#ga1d1813eb6bfcfa54b190b272dce576ff",
"group__odp__scheduler.html#ga3f3af33a2a42b3a9d6e5e3f74bfcb03d",
"group__odp__system.html#ga097733956f2c5d31e289f5f0a1c67d32",
"group__odp__timer.html#ga373923bac02ccf5db59a1fe19c2b3220",
"group__odp__traffic__mngr.html#ga88e055cb1444a385c3bafca90fde5c6a",
"odp_crc_8c-example.html",
"structodp__comp__deflate__param.html#a4f98572231c607098362e9bd8d3acd75",
"structodp__ipsec__inbound__config__t.html#a2628cc5de9892618a94c60b8f561d1e6",
"structodp__ml__model__info__t.html#a2c5d5944379bc2590ec77ba3469c2586",
"structodp__pktout__queue__param__t.html",
"structodp__shm__capability__t.html",
"structodp__tm__query__info__t.html#ad36349c36ae1f0d8257165027b2815f3",
"unionodp__pktin__config__opt__t.html#afe657ca9ac5ce9ee0cbb27263b39eb2e"
];

var SYNCONMSG = 'click to disable panel synchronisation';
var SYNCOFFMSG = 'click to enable panel synchronisation';