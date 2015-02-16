DIRS=basic 
all: $(DIRS)

.PHONY: clean $(DIRS)

$(DIRS):
	$(MAKE) -C $@ $(TARGET)

clean:
	for d in $(DIRS); do $(MAKE) -C $$d clean; done
