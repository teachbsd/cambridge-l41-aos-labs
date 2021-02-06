LAB1_TARBALL=2020-2021-advopsys-lab1.tbz
LAB1_FILES=					\
	LICENSE					\
	io/io.c					\
	2020-2021-l41-lab1.ipynb

LAB2345_TARBALL=2020-2021-advopsys-lab2345.tbz
LAB2345_FILES=					\
	LICENSE					\
	ipc/ipc.c				\
	2020-2021-l41-lab2345.ipynb

ALL=${LAB1_TARBALL} ${LAB2345_TARBALL}

all: ${ALL}
clean:
	rm -f ${ALL}

${LAB1_TARBALL}: ${LAB1_FILES}
	tar -czf ${LAB1_TARBALL} ${LAB1_FILES}

${LAB2345_TARBALL}: ${LAB2345_FILES}
	tar -czf ${LAB2345_TARBALL} ${LAB2345_FILES}
