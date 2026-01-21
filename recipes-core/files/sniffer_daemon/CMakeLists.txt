project(sniffer C)
add_executable(sniffer sniffer/main.c)
target_link_libraries(sniffer pthread)

project(sniffer_cli C)
add_executable(sniffer_cli cli/main.c)

install(TARGETS sniffer_cli DESTINATION bin)
install(TARGETS sniffer DESTINATION bin)

install(FILES sniffer.service DESTINATION /etc/systemd/system)