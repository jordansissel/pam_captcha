

pam:
	gcc -Wunused -c -fPIC -DHAVE_SHADOW -O2 pam_captcha.c
	ld -o pam_captcha.so -s -lpam -lcrypt --shared pam_captcha.o


