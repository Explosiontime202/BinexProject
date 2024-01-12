cmake_minimum_required(VERSION 3.18)
project(project C)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS "-Wall -Werror -g -fstack-protector -fshort-enums -z noexecstack -z relro -z now -pie -fPIE -Wl,-z,relro,-z,now")

add_executable(vuln vuln.c)
