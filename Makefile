

pam:
	gcc $(CFLAGS) -Wunused -c -fPIC -DHAVE_SHADOW -O2 pam_captcha.c
	gcc $(LDFLAGS) -o pam_captcha.so -s -lpam -lcrypt --shared pam_captcha.o
