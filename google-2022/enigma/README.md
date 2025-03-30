# Google CTF 2022 Writeup - Enigma

Hi, and welcome to this writeup for the crypto Enigma challenge.

At the end of the CTF, it had 9 solves and awarded 373 points. My team (PolyHx) was the 4th to crack it.

## Introduction

Since I've always had a passion for cryptography, I was interested as soon as I saw the challenge title.

A teammate told me that there was a similar challenge in a french CTF recently so I thought I could get some inspiration from there.

All the code written for this challenge is available here: https://git.step.polymtl.ca/romain/googlectf-enigma

## Exploration

The first thing I did was download the [attachment](https://storage.googleapis.com/gctf-2022-attachments-project/c549d32fbc247412db5a78293bf0bee9a51101afe9b3a5f302e467e987b6e0bd784d70bde0ad323c87a12c814dd8e4402ff92574a9f5e627f9ec4f818f44e413) which contained a software emulation of an [Enigma machine from WWII](https://en.wikipedia.org/wiki/Enigma_machine), which was used by the germans to send encryted messages to their army.

The summary of the challenge is as follows :

> Cryptanalysis has advanced a long way.
Can you break Enigma without a known plaintext?
The flag is written in all caps, with spaces and punctuation between words. It does not contain quotes.

To test the machine provided by Google, you can compile it by running `make -C enigma` then you can test it using example messages from the `messages` folder. For example:

```shell
$ ./enigma/machine VI III II NRS AO BH CU DL FM GW JZ KY PX QV XKR < messages/may_09_2022/comet.plaintext.txt | head
PQVT DKAD UQWA OUEU XPZI XBRK BYLY FZHG OUTZ QUSF
LZJV UOPL XTMF DOTM TLSS AHDN ZVHX GVKA KGCV ZSXX
RXEA DBTO MBXY GURD XGFI LOLD ROIE TZRF UIHD LZTN
EUXP NPIQ YBCF JVHG APZH MVTX YROM QHPX BZPE DKKM
MCTQ FASQ FBSF VGYN AVIT INGU XDPE VNRH WLHM AJKG
IMWM EKKN KKKJ UJJV GMNW LEFI BTSH UNAD DPCB TKOU
HHCZ HCPS KVQK VBWQ VLRC EZXI MPJI PIGF NAYH QSWX
UVUO WQVG MSFL MOSD ATNC CTUN HDVY ZLEO OGYC UXOA
WYND CGMM DBSK ABEK WWEJ SWLX BSEG UWJQ RVAZ EGEI
HFFL VQOX QZMS SASU BQOW HUDK KVPC GTXS MKFN RBBC
$ head messages/may_09_2022/comet.ciphertext.txt
PQVT DKAD UQWA OUEU XPZI XBRK BYLY FZHG OUTZ QUSF
LZJV UOPL XTMF DOTM TLSS AHDN ZVHX GVKA KGCV ZSXX
RXEA DBTO MBXY GURD XGFI LOLD ROIE TZRF UIHD LZTN
EUXP NPIQ YBCF JVHG APZH MVTX YROM QHPX BZPE DKKM
MCTQ FASQ FBSF VGYN AVIT INGU XDPE VNRH WLHM AJKG
IMWM EKKN KKKJ UJJV GMNW LEFI BTSH UNAD DPCB TKOU
HHCZ HCPS KVQK VBWQ VLRC EZXI MPJI PIGF NAYH QSWX
UVUO WQVG MSFL MOSD ATNC CTUN HDVY ZLEO OGYC UXOA
WYND CGMM DBSK ABEK WWEJ SWLX BSEG UWJQ RVAZ EGEI
HFFL VQOX QZMS SASU BQOW HUDK KVPC GTXS MKFN RBBC
```

Here, I encrypted the file `messages/may_09_2022/comet.plaintext.txt` using the settings from `messages/may_09_2022/settings`, and I got the contents of the file `messages/may_09_2022/comet.ciphertext.txt`

As explained in the README.md file, the Enigma machine can only encrypt/decrypt letters from A-Z, it doesn't support spaces, punctuation or accents. Once you find the correct key for cracking the Enigma machine, you can use the same key to perform a [Fernet](https://cryptography.io/en/latest/fernet/) decryption using the files `*.fernet.txt` in `messages` and get the original message with spaces and everything.

Now it's time to think about how we can crack it. The first thing to do is to search on your favorite search engine if anything similar has already been done. Since I knew a similar challenge was in the [404 CTF](https://ctftime.org/event/1646), I searched for "404 ctf enigma writeup". I found this link : https://mikelgarcialarragan.blogspot.com/2022/06/criptografia-ccxii-solucion-retos.html

After translating the page contents in English, I found this paragraph:
> This sounds like the challenge that I already put on this blog, "Challenge 43" , in which I explained the 'Ciphertext-only cryptanalysis of Enigma'  method proposed by  James   Gillogly . In summary, this method consists of three steps , the following:

Since I found the writeup to be kind of vague, I thought maybe I would find more information in this document from James Gillogly. I found the official article here: https://www.tandfonline.com/doi/abs/10.1080/0161-119591884060

You can read it for free if you are a student in most Universities, otherwise I was able to find it with a quick search without any restrictions.

The article explains basically how the Enigma machine worked and how by cracking even some of the key parameters, you can get a message closer to the plaintext after each step, until you recover the full key. According to the paper, you can crack Enigma in three steps:

1. Test all the rotors arrangement, with all the possible starting positions. There are 3 rotors to choose between 8 possibilities, and 26 possible starting positions for each chosen rotor. That's `8*7*6*26*26*26=5 905 536` keys to test. For each key, you have to give it a score using the "Index of Coincidence", which tells you how close the text is to a real language like German or English.

2. Using the key with the highest score from step 1, test all the possible ring settings, and keep the key with the best score. Here, we have `26*26*26=17 576` keys to test.

3. Using the best key from step 2, crack the plugboard one pair at a time, by always keeping the pair with the best Index of Coincidence score.

You should then have a key that converts the ciphertext to the original plaintext.

I also found a [video of Computerphile](https://www.youtube.com/watch?v=RzWB5jL5RX0) that said approximately the same thing about how to crack Enigma knowing only the ciphertext.

## First Try - Index of Coincidence

I wrote a script in C++ that used the library provided by the CTF to encrypt/decrypt a given text using a given key, and I tried to crack the rotors and initial positions of the message from May 09. After some time trying to understand how the library worked and how to implement the index of coincidence algorithm, I ended up with [this script](https://git.step.polymtl.ca/romain/googlectf-enigma/-/blob/97d47bbd3cf4c985f0f1fd178bb8ce6fc210d8d0/coincidence.cpp) that tried all possible rotor combinations and all initial positions and calculated the IoC score for each resulting key. At this point my ring settings were always AAA and my plugboard was always empty.

Unfortunately it didn't really work on the May 09 message, not finding the best settings. In order to understand what was going on, I tried cracking a text in French (my native tongue) that I generated from the Internet. My encryption key was `I II VI AAA AA AA AA AA AA AA AA AA AA AA AAA` ([link](https://git.step.polymtl.ca/romain/googlectf-enigma/-/blob/master/testdata/long.original)). After fixing some implementations problems, I got a script that worked for cracking my text, but not the one from the CTF. I also noticed that as soon as I was changing the ring settings or the plugboard, my script didn't work anymore. You can download this version of the script [here](https://git.step.polymtl.ca/romain/googlectf-enigma/-/tree/954ac0f262b5cf72a8661ddf01b49fb55055bbd5/) and run it like this:

```shell
$ g++ -O3 -std=c++17 crack.cpp fitness/ioc.cpp -o crack
$ ./crack 0 < testdata/long.cipher
Trying I, II, VI
I II VI - A A A : 0.0679531
Trying I, II, VII
I II VII - F R R : 0.0390398
Trying I, II, VIII
I II VIII - E A V : 0.038984
Trying I, III, VI
I III VI - Z I M : 0.0390436
Trying I, III, VII
I III VII - T Z N : 0.0391296
Trying I, III, VIII
I III VIII - P B W : 0.039076
Trying I, IV, VI
I IV VI - V U Z : 0.038967
Trying I, IV, VII
I IV VII - X X N : 0.0389954
...
I VII VI - L D M : 0.0390653
I VI V - E P Y : 0.0390732
I V VI - B O Y : 0.0390748
I III VIII - P B W : 0.039076
I V VIII - F X R : 0.039077
I VIII VI - U U B : 0.0390808
I VI VIII - C W E : 0.0390836
I III VII - T Z N : 0.0391296
I II VI - A A A : 0.0679531
```

We can see that the best version if easily the one with the right rotors and the right starting positions. However, if we run it with the May 09 message:

```shell
$ ./crack 5 < messages/may_09_2022/comet.ciphertext.txt
...
Trying VI, III, II
VI III II - W A W : 0.0388875
Trying VI, III, IV
VI III IV - T D F : 0.038932
Trying VI, III, V
VI III V - G K P : 0.038925
...
VI II III - G N A : 0.0389827
VI IV II - O I V : 0.0390001
VI VIII V - Z U W : 0.0390086
VI V III - W H T : 0.0390188
VI VIII VII - K E B : 0.0391073
```

The text with the best score isn't even the one with the right rotors (VI III II).

## Second Try - Quadgrams

Since the first method didn't seem to work with messages that had many plugboard settings, I looked for other ways to crack Enigma.

After searching for "Cryptanalysis of Enigma", I found [this page](http://practicalcryptography.com/cryptanalysis/breaking-machine-ciphers/cryptanalysis-enigma/) that used quadgrams statictics to give a score to each message, I tried implementing it and I modified my script to support using different "fitness" algorithms to choose the best keys. You can test it with the same files as the first try but these commands:

```shell
$ make clean
rm -rf crack text_ioc
$ make
g++ -g -std=c++17 text_ioc.cpp fitness/quadgrams.cpp -o text_ioc
g++ -O3 -std=c++17 crack.cpp fitness/quadgrams.cpp -o crack
# The text_ioc program just gives a score to the text sent in stdin, for debugging
$ ./crack 0 < testdata/long.cipher
Trying I, II, VI
I II VI - A A A : -14010
Trying I, II, VII
I II VII - W L Z : -21203.9
```

This time, the scores are negative, but the highest one is supposed to be closer to plaintext than the other ones. Again, the algorithm worked for my test message, but not for the ones in `messages`. However the [part 2](http://practicalcryptography.com/cryptanalysis/breaking-machine-ciphers/cryptanalysis-enigma-part-2/) of the page talked about another paper by "Heidi Williams" called [Applying Statistical Language Recognition Techniques in the Ciphertext only Cryptanalysis of Enigma](https://www.tandfonline.com/doi/abs/10.1080/0161-110091888745).

## Third Try - Sinkov Unigrams

This new paper explained why Quadgrams and the Index of Coincidence algorithms didn't work well for messages with many plugs in the plugboard. It's mainly because with 10 plugs, that means 20 letters out of 26 are swapped in your messages and it's difficult to precisely detect the difference between the good solution and random noise. It also explains why you should not just keep the best key for each step, but up to the 3000 best keys, and then try to crack the ring settings again with the best keys after cracking the plugboard.

Since that required a lot of compute power, I implemented threading in my program in [this commit](https://git.step.polymtl.ca/romain/googlectf-enigma/-/commit/e5a43e98cd1a8971378db4898e8a312a6246abaf) and I used a virtual machine hosted at [OVHCloud](https://us.ovhcloud.com/public-cloud/prices/) (flavor c2-120, 32 vCores, 120GB RAM).

I then proceeded to implement the Sinkov algorithm, using unigram frequencies from [here](http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/german-letter-frequencies/). I had four main functions, with four threaded functions:

| Main function        | Threaded function    | Iterations | Threads |
|----------------------|----------------------|------------|---------|
| find_rotor_order     | try_all_keys         | 4 850 976  | 276     |
| adjust_ring_settings | try_adjust_ring      | 52 728 000 | 3000    |
| adjust_plugboard     | try_adjust_plugboard | 4 575 000  | 3000    |
| finalAdjust          | try_final            | 456 976    | 676     |

Iterations: Number of possible keys tried in the function. These are spread across the indicated number of threads.

`find_rotor_order` finds the 3000 best rotor settings and initial positions, then `adjust_ring_settings` finds the best ring setting for each of the 3000 best results, then same for `adjust_plugboard`, which finds the best plugboard configuration for each of the 3000 results from before, then `finalAdjust` cracks the initial positions and ring settings again from the best result after `adjust_plugboard`. This should give you the right key for cracking basically any message. For better results, I used the Sinkov algorithm for `find_rotor_order` and `adjust_ring_settings`, then Quadgrams for `adjust_plugboard` and `finalAdjust`. We can now crack `messages/may_09_2022/comet.ciphertext.txt` using this command:

```shell
$ make clean && make
$ ./crack 0 < messages/may_09_2022/comet.ciphertext.txt
```

After running for ~10 minutes, we get this output: https://pastebin.com/UeW7KeSB

When we decrypt the cipher using the resulting key, we get exactly the same output as what was originally encrypted:

```shell
$ ./enigma/machine VI III II VRS AO BH CU DL FM GW JZ KY PX QV FKR < messages/may_09_2022/comet.ciphertext.txt | diff /dev/stdin ./messages/may_09_2022/comet.plaintext.txt -s

Files /dev/stdin and ./messages/may_09_2022/comet.plaintext.txt are identical
```

However, the key is not exactly the same, the leftmost ring setting and initial position differ. I eventually understood that for each leftmost ring setting, there was an equivalent leftmost initial position that gave exactly the same result, so I added a `find_all_solutions` function that computed for the best key what were the right initial positions for each leftmost ring setting. The CTF team later published an updated script for `encrypt_modern.py` that converted our key to one that would always work for the Fernet cipher, with a leftmost ring setting forced to "A".

Another problem that was also later fixed by the CTF team, was the order of the plugs in the plugboard. It doesn't matter if you use the first or the second version of this same key where the order of plugboard pairs differ:

```
VI III II VRS AO BH CU DL FM GW JZ KY PX QV FKR
VI III II VRS QV PX KY JZ GW FM DL CU BH AO FKR
```

## Final cracking

With a script that worked for my debugging text and the one from `messages/may_09_2022`, I then started cracking the real cipher:

```shell
$ ./crack 0 < messages/may_12_2022/flag.ciphertext.txt
...
1 : VII IV I ZSN AH BO CL DU FW GM JY KZ PV QX AJR : -12325.1
2 : VII IV I ZRN AH BO CL DU FW GM JY KZ PV QX AIR : -12880.6
3 : VII IV I ZSM AH BO CL DU FW GM JY KZ PV QX AJQ : -12947.5
...
$ ./enigma/machine VII IV I ZSN AH BO CL DU FW GM JY KZ PV QX AJR < messages/may_12_2022/flag.ciphertext.txt
$ ./encrypt_modern.py decrypt VII IV I ZSN AH BO CL DU FW GM JY KZ PV QX AJR < messages/may_12_2022/flag.fernet.txt

Traceback (most recent call last):
  File "/home/romain/dev/googlectf/googlectf-enigma/./encrypt_modern.py", line 54, in <module>
    plaintext = f.decrypt(ciphertext)
  File "/home/romain/dev/googlectf/googlectf-enigma/env/lib/python3.10/site-packages/cryptography/fernet.py", line 83, in decrypt
    timestamp, data = Fernet._get_unverified_token_data(token)
  File "/home/romain/dev/googlectf/googlectf-enigma/env/lib/python3.10/site-packages/cryptography/fernet.py", line 115, in _get_unverified_token_data
    raise InvalidToken
cryptography.fernet.InvalidToken
```

Here are the logs : https://pastebin.com/E8nFjBn1

Key : `VII IV I ZSN AH BO CL DU FW GM JY KZ PV QX AJR`

Correct key (released later): `VII IV I ATN AH BO CL DU FW GM JY KZ PV QX CLR`

It really seemed to have worked, since the best solution had a score much higher than even the second best one, and the resulting text seemed to contain valid words like "FLAG" or "EIN". However, even using the fixed script that used the right leftmost ring setting and the plugboard in alphabetical order, I couldn't decrypt the fernet text using my key.

## Parsing the plaintext

Since I was sure that what I had was the correct plaintext, but I couldn't read it because it lacked spaces and punctuation, and I don't speak a single word of German, I thought maybe Google Translate would be able to understand it if I added spaces using a wordlist to guess where the spaces should be.

All the code related to this part is in the [flag-solve](https://git.step.polymtl.ca/romain/googlectf-enigma/-/tree/master/flag-solve) folder of my repository. Here is a description of all the files:

- myresult.txt: The decrypted text.
- compact: The decrypted text with all spaces and line breaks removed.
- wordlist-german.txt: A list of most used german words.
- new-wordlist.txt: The same wordlist but with each word converted using `prepare_wordlist.py`.
- prepare_wordlist.py: A script to encode all the words in the wordlist to only use ASCII all-caps characters.
- parse.py: A script to guess where spaces should be using the wordlist and replace special letters (J -> '"', X -> '.', Y -> ',').

After running the script, putting the output in Google Translate, and trying to correct the errors with the help of a friend that spoke a little bit of German, we got this text:

```
LIEBE WETTBEWERBER, DIE FLAGGE BEGINNT  MIT EINEM GROSSEN "C", EINEM GROSSEN "T" UND "F". DARAUF FOLGT  EINE OFFEN EGESCHWIFFENE KLAMMER. DER  LETZTE BUCHSTABE IST EINE GESCHLOSSEN EGESCHWIFFENE KLAMMER. ZWISCHEN DIESEN KLAMMERN STEHEN EINIGE ANDERE BUCHSTABEN. DER  ERSTE BUCHSTABE ZWISCHEN DEN KLAMMERN IST 'D'. DER ZWEITE BUCHSTABE ZWISCHEN DEN KLAMMERN IST  'U'. DER  DRITTE BUCHSTABE ZWISCHEN DEN KLAMMERN IST "H". DER  VIERTE BUCHSTABE ZWISCHEN DEN KLAMMERN IST "A". DER FUENFTE BUCHSTABE ZWISCHEN DEN KLAMMERN IST "S". DARAUF FOLGT "T GE". DA  NACH KOMMT "TAN". WEITER  HIN KOMMT NUN ", WAS " WORAUF" TURING" FOLGT. DIE  LETZTEN BUCH STABEN SIND "N","I","CHT KONNTE".
```

I then submitted the flag `CTF-{DU HAST GETAN, WAS TURING NICHT KONNTE}`, which worked !

## Conclusion

I really enjoyed this challenge, that required a lot of reading, but also good programming skills and even some ability to understand German in some cases. I learned a lot about how the Enigma machine worked, but also how you can use statistics to evaluate the quality of a partially decrypted text, and also how to use threading and cloud platforms to bruteforce a cipher algorithm.

There are also a lot of things I could have done better. For example, if I had read more patiently the information available to me, I would have avoided a lot of rabbit holes, because I just didn't understand how some aspects of Enigma worked, like the leftmost ring setting that doesn't change the decryption result. I also should have tested my code one part at a time to discover my implementation errors earlier. Finally, I probably could have saved a lot of CPU time by just keeping less "good results" and running one part at a time, instead of re-solving everything when I had an error at the third or fourth step.

Even in the context of a competition with limited time, you have to remember to take a break, try to pause and understand what you are doing, talk about it with your teammates, in order to solve a complex problem.

## Bonus

What htop looked like while cracking Enigma: ![htop screenshot](htop.png)

## References

Here is a list of URLs that helped me solve this challenge.

- https://www.tandfonline.com/doi/abs/10.1080/0161-119591884060 : The first paper
- https://www.tandfonline.com/doi/pdf/10.1080/0161-110091888745 : The second paper
- http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/german-letter-frequencies/ : German letter frequencies
- https://www.alphr.com/artificial-intelligence/1007869/how-ai-could-have-cracked-the-enigma-code-and-helped-end-wwii-in/ : An article about cracking Enigma with Artificial Intelligence
- https://gist.github.com/MarvinJWendt/2f4f4154b8ae218600eb091a5706b5f4 : The german wordlist
- https://cryptocellar.org/pubs/enigma-modern-breaking.pdf : Another paper about breaking Enigma
- http://practicalcryptography.com/cryptanalysis/breaking-machine-ciphers/cryptanalysis-enigma-part-2/ : The website used in Second Try
- https://us.ovhcloud.com/public-cloud/ : The cloud platform I used for a powerful virtual machine
- https://www.youtube.com/watch?v=RzWB5jL5RX0 : The Computerphile video
- https://github.com/mikepound/enigma : The code from the Computerphile video
- https://git.step.polymtl.ca/romain/googlectf-enigma : My Git repository
- https://translate.google.com/ : A website useful when trying to understand german

I would also like to thank [PolyHx](https://polycyber.io/) for inviting me in their CTF team, [Polytechnique Montréal](https://polymtl.ca/) for giving me access to countless academic papers online, and [Jimmy Bell](https://github.com/Ch0ufleur) for helping me translate my German plaintext into understandable text.
