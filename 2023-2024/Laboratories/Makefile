LAB1_TARBALL=2023-2024-advopsys-lab1.tbz
LAB1_FILES=					\
	LICENSE					\
	jupyter_notebook_config.py		\
	2023-2024-advopsys-lab1.ipynb

LAB2_TARBALL=2023-2024-advopsys-lab2.tbz
LAB2_FILES=					\
	LICENSE					\
	jupyter_notebook_config.py		\
	ipc/ipc.c				\
	ipc/Makefile				\
	2023-2024-advopsys-lab2.ipynb

LAB3_TARBALL=2023-2024-advopsys-lab3.tbz
LAB3_FILES=					\
	LICENSE					\
	jupyter_notebook_config.py		\
	2023-2024-advopsys-lab3-dtrace.ipynb	\
	2023-2024-advopsys-lab3-partii.ipynb

ALL=${LAB1_TARBALL} ${LAB2_TARBALL} ${LAB3_TARBALL} \

all: ${ALL}
distribute: all
	python3 distribute.py

clean:
	rm -f ${ALL}

${LAB1_TARBALL}: ${LAB1_FILES} Makefile
	tar -czf ${LAB1_TARBALL} ${LAB1_FILES}

${LAB2_TARBALL}: ${LAB2_FILES} Makefile
	tar -czf ${LAB2_TARBALL} ${LAB2_FILES}

${LAB3_TARBALL}: ${LAB3_FILES} Makefile
	tar -czf ${LAB3_TARBALL} ${LAB3_FILES}
