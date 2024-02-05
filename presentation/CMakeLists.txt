set(LATEX_SOURCE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/presentation.tex")

add_custom_target(presentation
        COMMAND latexmk -pdf ${LATEX_SOURCE_FILE} -output-directory=build
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMENT "Building LaTeX presentation"
        SOURCES ${LATEX_SOURCE_FILE}
)

add_custom_target(add_decoy
	COMMAND pdftk ../DolphinsDecoy.pdf presentation.pdf cat output full_presentation.pdf
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build
	COMMENT "Cha Cha real smooth"
	SOURCES ${presentation}
)
