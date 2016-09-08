JFLAGS = -g
JC = javac

.SUFFIXES: .java .class

.java.class:
	$(JC) $(JFLAGS) $*.java

CLASSES = \
    Server.java \
    Client.java \

default: clean classes 

classes: $(CLASSES:.java=.class)

.PHONY: clean
clean:
	rm -f *.class
