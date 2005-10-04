FILE=../lib/Funknet/Whois/ObjectDefs.pm

$(FILE): templates.txt generate.pl
	perl generate.pl > $(FILE)

all: $(FILE)

.PHONY: $(FILE)
