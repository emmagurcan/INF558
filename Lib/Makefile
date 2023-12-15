all: tools crypto

tools: /dev/null # to please the make under win*
	cd Tools; make

crypto: /dev/null # to please the make under win*
	cd Crypto; make

##### install the doxygen package, probably along with graphviz
##### it will produce html and latex output which are quite nice
Doxyfile: /dev/null # to please the make under win*
	doxygen -g
##	sed 's/OPTIMIZE_OUTPUT_FOR_C  = NO/OPTIMIZE_OUTPUT_FOR_C  = YES/' Doxyfile > /tmp/foo

doc: doxygen
	mv latex/refman.pdf inf558_lib.pdf

doxygen: Doxyfile.inf558
	doxygen Doxyfile.inf558
	cd latex; pdflatex refman; makeindex refman; pdflatex refman

clean: /dev/null # to please the make under win*
	cd Tools; make clean
	cd Crypto; make clean
