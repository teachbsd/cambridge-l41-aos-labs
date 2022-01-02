LAB1_TARBALL=2021-2022-advopsys-lab1.tbz
LAB1_FILES=					\
	LICENSE					\
	io/io.c					\
	io/Makefile				\
	2021-2022-l41-lab1.ipynb

LAB2_TARBALL=2021-2022-advopsys-lab2.tbz
LAB2_FILES=					\
	LICENSE					\
	ipc/ipc.c				\
	ipc/Makefile				\
	2021-2022-l41-lab2.ipynb

ALL=${LAB1_TARBALL} ${LAB2_TARBALL}

all: ${ALL}
clean:
	rm -f ${ALL}

${LAB1_TARBALL}: ${LAB1_FILES} Makefile
	tar -czf ${LAB1_TARBALL} ${LAB1_FILES}

${LAB2_TARBALL}: ${LAB2_FILES} Makefile
	tar -czf ${LAB2_TARBALL} ${LAB2_FILES}
