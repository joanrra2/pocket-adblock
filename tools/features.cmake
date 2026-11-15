# Turns FEATURES.cfg (or -D FEATURES_FILE=flavours/<name>.cfg) into Kconfig
# values. Included from the top-level CMakeLists.txt before project():
#  - writes <build>/features.defaults and appends it to SDKCONFIG_DEFAULTS
#    (new / regenerated sdkconfig files get the values), and
#  - rewrites the same options in an existing sdkconfig, so editing the file
#    and rebuilding is enough (ESP-IDF doesn't re-apply defaults by itself).
# The edition (CONFIG_SINKHOLE_FLAVOUR) is the preset's file name for files in
# flavours/, otherwise "custom".

if(NOT DEFINED FEATURES_FILE)
    set(FEATURES_FILE "${CMAKE_SOURCE_DIR}/FEATURES.cfg")
endif()
get_filename_component(FEATURES_FILE "${FEATURES_FILE}" ABSOLUTE BASE_DIR "${CMAKE_SOURCE_DIR}")
if(NOT EXISTS "${FEATURES_FILE}")
    message(FATAL_ERROR "features file not found: ${FEATURES_FILE}")
endif()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${FEATURES_FILE}")

get_filename_component(_feat_dir "${FEATURES_FILE}" DIRECTORY)
get_filename_component(_feat_name "${FEATURES_FILE}" NAME_WE)
if(_feat_dir STREQUAL "${CMAKE_SOURCE_DIR}/flavours")
    set(_flavour "${_feat_name}")
else()
    set(_flavour "custom")
endif()

# FEATURES key -> Kconfig option (without CONFIG_), and kind.
set(_bool_map
    ENABLE_LONG_HISTORY=SINKHOLE_QUERY_HISTORY_EXTENDED
    ENABLE_BLOOM_FILTER=SINKHOLE_BLOOM_FILTER
    ENABLE_DNS_OVER_TLS=SINKHOLE_DNS_OVER_TLS
    ENABLE_TOP_DOMAINS=SINKHOLE_TOP_DOMAINS)
set(_int_map
    LONG_HISTORY_ENTRIES=SINKHOLE_QUERY_HISTORY_ENTRIES
    TOP_DOMAINS_ENTRIES=SINKHOLE_TOP_DOMAINS_ENTRIES)

file(STRINGS "${FEATURES_FILE}" _lines)
set(_values "")
foreach(_line IN LISTS _lines)
    string(REGEX REPLACE "#.*$" "" _line "${_line}")
    if(_line MATCHES "^[ \t]*([A-Z0-9_]+)[ \t]*=[ \t]*([0-9]+)[ \t]*$")
        set(_val_${CMAKE_MATCH_1} "${CMAKE_MATCH_2}")
    elseif(NOT _line MATCHES "^[ \t]*$")
        message(FATAL_ERROR "${FEATURES_FILE}: can't read line '${_line}' (expected NAME = number)")
    endif()
endforeach()

set(_defaults "# generated from ${FEATURES_FILE}\n")
set(_wanted "")  # "OPTION|line" pairs to enforce in an existing sdkconfig
foreach(_pair IN LISTS _bool_map)
    string(REPLACE "=" ";" _kv "${_pair}")
    list(GET _kv 0 _key)
    list(GET _kv 1 _opt)
    if(NOT DEFINED _val_${_key})
        message(FATAL_ERROR "${FEATURES_FILE}: ${_key} is missing")
    endif()
    if(_val_${_key})
        set(_l "CONFIG_${_opt}=y")
        set(_on_${_opt} TRUE)
    else()
        set(_l "# CONFIG_${_opt} is not set")
    endif()
    string(APPEND _defaults "${_l}\n")
    list(APPEND _wanted "${_opt}|${_l}")
endforeach()
foreach(_pair IN LISTS _int_map)
    string(REPLACE "=" ";" _kv "${_pair}")
    list(GET _kv 0 _key)
    list(GET _kv 1 _opt)
    if(DEFINED _val_${_key})
        string(APPEND _defaults "CONFIG_${_opt}=${_val_${_key}}\n")
        list(APPEND _wanted "${_opt}|CONFIG_${_opt}=${_val_${_key}}")
    endif()
endforeach()
string(APPEND _defaults "CONFIG_SINKHOLE_FLAVOUR=\"${_flavour}\"\n")
list(APPEND _wanted "SINKHOLE_FLAVOUR|CONFIG_SINKHOLE_FLAVOUR=\"${_flavour}\"")

file(MAKE_DIRECTORY "${CMAKE_BINARY_DIR}")
set(_defaults_file "${CMAKE_BINARY_DIR}/features.defaults")
file(WRITE "${_defaults_file}" "${_defaults}")
if(NOT DEFINED SDKCONFIG_DEFAULTS)
    if(DEFINED ENV{SDKCONFIG_DEFAULTS})
        set(SDKCONFIG_DEFAULTS "$ENV{SDKCONFIG_DEFAULTS}")
    else()
        set(SDKCONFIG_DEFAULTS "sdkconfig.defaults")
    endif()
endif()
list(APPEND SDKCONFIG_DEFAULTS "${_defaults_file}")

# Existing sdkconfig: rewrite only these options' lines (options it doesn't
# have yet come from the defaults above).
if(DEFINED SDKCONFIG)
    get_filename_component(_sdkconfig "${SDKCONFIG}" ABSOLUTE BASE_DIR "${CMAKE_SOURCE_DIR}")
else()
    set(_sdkconfig "${CMAKE_SOURCE_DIR}/sdkconfig")
endif()
if(EXISTS "${_sdkconfig}")
    file(READ "${_sdkconfig}" _cfg)
    set(_orig "${_cfg}")
    foreach(_w IN LISTS _wanted)
        string(FIND "${_w}" "|" _bar)
        string(SUBSTRING "${_w}" 0 ${_bar} _opt)
        math(EXPR _bar "${_bar} + 1")
        string(SUBSTRING "${_w}" ${_bar} -1 _line)
        string(REGEX REPLACE "(^|\n)(CONFIG_${_opt}=[^\n]*|# CONFIG_${_opt} is not set)(\n|$)" "\\1${_line}\\3" _cfg "${_cfg}")
    endforeach()
    if(NOT _cfg STREQUAL _orig)
        file(WRITE "${_sdkconfig}" "${_cfg}")
        message(STATUS "features: applied ${FEATURES_FILE} to ${_sdkconfig}")
    endif()
endif()
message(STATUS "features: ${_flavour} edition (${FEATURES_FILE})")
