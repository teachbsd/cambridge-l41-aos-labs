LAB1_TARBALL=2020-2021-advopsys-lab1.tbz
LAB1_FILES=					\
	LICENSE					\
	io/io.c					\
	io/Makefile				\
	2020-2021-l41-lab1.ipynb

LAB2_TARBALL=2020-2021-advopsys-lab2.tbz
LAB2_FILES=					\
	LICENSE					\
	ipc/ipc.c				\
	ipc/Makefile				\

LAB3_TARBALL=2020-2021-advopsys-lab3.tbz
LAB3_FILES=					\
	LICENSE					\
	ipc/ipc.c				\
	ipc/Makefile				\
	2020-2021-l41-lab3.ipynb

ALL=${LAB1_TARBALL} ${LAB2_TARBALL} ${LAB3_TARBALL}

all: ${ALL}
clean:
	rm -f ${ALL}

${LAB1_TARBALL}: ${LAB1_FILES} Makefile
	tar -czf ${LAB1_TARBALL} ${LAB1_FILES}

${LAB2_TARBALL}: ${LAB2_FILES} Makefile
	tar -czf ${LAB2_TARBALL} ${LAB2_FILES}

${LAB3_TARBALL}: ${LAB3_FILES} Makefile
	tar -czf ${LAB3_TARBALL} ${LAB3_FILES}
