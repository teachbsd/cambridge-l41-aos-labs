LAB1_TARBALL=2026-2027-advopsys-lab1.tbz
LAB1_FILES=					\
	LICENSE					\
	jupyter_notebook_config.py		\
	2026-2027-advopsys-lab1.ipynb

LAB2_TARBALL=2026-2027-advopsys-lab2.tbz
LAB2_FILES=					\
	LICENSE					\
	jupyter_notebook_config.py		\
	ipc					\
	2026-2027-advopsys-lab2.ipynb		\
	2026-2027-advopsys-lab2-dtrace.ipynb

ALL=${LAB1_TARBALL} ${LAB2_TARBALL}

all: ${ALL}
distribute: all
	python3 distribute.py

clean:
	rm -f ${ALL}

${LAB1_TARBALL}: ${LAB1_FILES} Makefile
	tar -czf ${LAB1_TARBALL} ${LAB1_FILES}

${LAB2_TARBALL}: ${LAB2_FILES} Makefile
	tar -czf ${LAB2_TARBALL} ${LAB2_FILES}
