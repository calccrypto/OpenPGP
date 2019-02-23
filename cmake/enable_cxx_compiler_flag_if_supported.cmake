cmake_minimum_required(VERSION 3.6.0)

# modified from https://stackoverflow.com/a/33266748/341683
# by Quantumboredom
include(CheckCXXCompilerFlag)

function(enable_cxx_compiler_flag_if_supported variable flag)
    string(FIND "${${variable}}" "${flag}" flag_already_set)
    if(flag_already_set EQUAL -1)
        check_cxx_compiler_flag("${flag}" flag_supported)
        if(flag_supported)
            set(${variable} "${${variable}} ${flag}" PARENT_SCOPE)
        endif()
        unset(flag_supported CACHE)
    endif()
endfunction()
