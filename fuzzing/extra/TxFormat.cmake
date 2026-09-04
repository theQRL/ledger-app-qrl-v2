# Display formatters (SDK-free): amount/fee rendering shown before user approval.
add_library(txformat
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui/tx_format.c
)

set_target_properties(txformat PROPERTIES SOVERSION 1)

target_include_directories(txformat PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../unit-tests/stubs
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/ui
)
