test:
	python3 kat_test.py | tee run10.log
	cat run10.log kat/kat10.txt | grep -v '#' | sort | uniq -c -w 64
	@echo "     >2< here means that the test vectors match!" 
clean:
	$(RM) -f *.pyc *.cprof */*.pyc *.rsp *.log
	$(RM) -rf __pycache__ */__pycache__

