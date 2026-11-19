idf_component_register(SRCS "web_server.cpp" "json_writer.cpp"
                       INCLUDE_DIRS "include"
                       REQUIRES core blocklist dns stats update net wol led notify esp_http_server
                       PRIV_REQUIRES log esp_system esp_timer mbedtls)

# The UI lives in /www as plain HTML; it is gzipped at build time and embedded.
idf_build_get_property(python PYTHON)
set(www_src "${PROJECT_DIR}/www/index.html")
set(www_gz "${CMAKE_CURRENT_BINARY_DIR}/index.html.gz")
add_custom_command(OUTPUT "${www_gz}"
                   COMMAND ${python} "${PROJECT_DIR}/tools/gzip_asset.py" "${www_src}" "${www_gz}"
                   DEPENDS "${www_src}" "${PROJECT_DIR}/tools/gzip_asset.py"
                   VERBATIM)
add_custom_target(web_assets DEPENDS "${www_gz}")
target_add_binary_data(${COMPONENT_LIB} "${www_gz}" BINARY DEPENDS web_assets)
