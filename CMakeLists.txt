cmake_minimum_required(VERSION 3.27)
project(project C)

set(CMAKE_C_STANDARD 17)

set(CMAKE_C_FLAGS "-Wall -Werror -g")

add_executable(vuln vuln.c)
