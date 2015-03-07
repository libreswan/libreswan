ifneq ($(strip $(XMLTO)),)
%.8: %.8.xml
	${XMLTO} man $< 
	@for m in ipsec_*.8; do if [ -f $$m ]; then mv $$m $@; fi; done

%.5: %.5.xml
	${XMLTO} man $< 
	@for m in ipsec_*.5; do if [ -f $$m ]; then mv $$m $@; fi; done

%.2: %.2.xml
	${XMLTO} man $< 
	@for m in ipsec_*.3; do if [ -f $$m ]; then mv $$m $@; fi; done

%.1: %.1.xml
	${XMLTO} man $< 
	@for m in ipsec_*.1; do if [ -f $$m ]; then mv $$m $@; fi; done
endif

