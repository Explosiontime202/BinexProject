set(LATEX_SOURCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/presentation.tex")

add_custom_target(presentation
        COMMAND latexmk -pdf ${LATEX_SOURCE_FILE} -output-directory=build
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Building LaTeX presentation"
        SOURCES ${LATEX_SOURCE_FILE}
)
