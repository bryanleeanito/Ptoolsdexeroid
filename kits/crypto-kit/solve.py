#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""solve.py - penyelesai cipher & kripto CTF (kategorinya: kriptografi).

Berhenti menebak-nebak: kenali dulu bentuknya, lalu serang dengan metode yang
benar. Semua berjalan offline, stdlib murni (Cryptodome dipakai kalau ada,
tapi bukan syarat).

    python3 solve.py "khoor zruog"                 # auto-kenali + coba semua
    python3 solve.py --caesar "khoor zruog"
    python3 solve.py --substitution "..."          # cipher alfabet tunggal
    python3 solve.py --xor "0a1b2c..."             # 1 byte + kunci berulang
    python3 solve.py --vigenere "..."              # deteksi panjang kunci
    python3 solve.py --rail "..."                  # rail fence
    python3 solve.py --hash 5d41402abc4b2a76...    # kenali + pecahkan
    python3 solve.py --hash ... --wordlist list.txt
    python3 solve.py --rsa --n N --e E --c C       # serangan RSA
    python3 solve.py --rsa --n n1 --n n2           # gcd antar modulus
    python3 solve.py --aes --hex 53616c7361...     # deteksi ECB/CBC + dekrip
    python3 solve.py --auto --in cipher.txt

DESAIN: tiap penyelesai mengembalikan (key, plaintext, skor) terurut, bukan
hanya satu hasil. Di CTF soalnya sering ambigu - kamu yang memutuskan mana
yang masuk akal dari beberapa kandidat.
"""
from __future__ import annotations

import argparse
import hashlib
import math
import re
import string
import sys
from collections import Counter

# =========================================================== kosakata Inggris
# Dipakai utk menilai hasil. Bukan kamus penuh - cukup yang paling sering muncul
# di plaintext CTF (kebanyakan soal berbahasa Inggris).
KATA_UMUM = frozenset("""
the of and to in a is that for it as with be by on or not you all had we one
their said what been has when who will more no if out so up into do time each
which there use can may first other then now find any new work part take get
like long make well even back most people its over state year good could our
after than just such some these would them see way been many too little word
about them these her would make like him into time has look two more write go
see number no way could people my first water been call who oil its now find
long down day did get come made may part called use each how she all way
file data key value name text user pass code byte bit json xml http request
admin login secret flag hidden message encoded secret cipher encrypt decrypt
password token secret hidden secret correct success denied welcome message
house man woman child road street river town city school student teacher book
morning night light dark water food shop church window room door floor table
chair wall garden tree flower bird animal horse dog cat house small large
old young great little high low near far left right front back first last
same other another every some none both few many much most least more less
than then when where what which while who whom whose because before after
above below under between during without within against toward along among
help show try keep stop start turn move place hand head eye face foot arm
leg body heart mind thought idea question answer problem reason result thing
nothing everything something anything nobody everybody somebody anybody
always never often sometimes usually again already still yet soon later
today yesterday tomorrow here there everywhere somewhere nowhere maybe
perhaps almost quite rather very really actually certainly probably
team group member manager company money market report sales product line
design change system process method result note record test check run work
ready enough possible difficult important different several particular
really complete whole entire total number amount value size length width
""".split())

FREK_EN = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}
ALF = string.ascii_lowercase

BIGRAM_UMUM = frozenset("""
th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se
ha as ou io le ve co me de hi ri ro ic ne ea ra li ch ll be ma si om ur
""".split())

TRIGRAM_UMUM = frozenset("""
the and ing her hat his tha ere for was you but not all we can out are has
his one our now new was two its who get see him time than may like so this
""".split())


def _bangun_statistik(korpus: str):
    """Hitung bigram/trigram dari korpus yang DITANAM di file ini.

    Kenapa begini, bukan tabel angka mati? Angka frekuensi yang dikarang
    sendiri bikin hill-climb substitusi nyangkut di local optimum -
    hasilnya kelihatan "mungkin" tapi bukan bahasa (EHA LUIDJ MROFN).
    Dengan korpus, statistiknya benar-benar diturunkan dari teks nyata, dan
    kamu bisa menambah isinya kalau mau akurasi lebih baik.
    """
    huruf = [c for c in korpus.lower() if c.isalpha()]
    n = max(1, len(huruf))
    big = Counter("".join(huruf[i:i + 2]) for i in range(len(huruf) - 1))
    tri = Counter("".join(huruf[i:i + 3]) for i in range(len(huruf) - 2))
    log_big = {k: math.log10((v + 0.5) / n) for k, v in big.items()}
    log_tri = {k: math.log10((v + 0.5) / n) for k, v in tri.items()}
    return (Counter(huruf), log_big, log_tri,
            min(log_big.values()) - 2.0, min(log_tri.values()) - 2.0)


KORPUS = """
the cat sat on the mat and the dog ran through the field where the children
were playing with their small red ball near the old wooden house by the river
when the sun went down behind the hills the whole town became quiet and only
the sound of the wind could be heard moving through the trees that stood along
the main road leading to the market square in the centre of the city

a group of people gathered outside the building to discuss the new rules that
the council had decided to introduce for the coming year because the old system
was not working well and everyone agreed that something had to be changed soon
the manager said that the company would need more time to finish the work and
that the team had already done a very good job with the limited resources

there are many different ways to solve a difficult problem and it is often
useful to look at the same question from another point of view before you
decide what to do next in order to avoid making a mistake that cannot be fixed
he asked her whether she had seen the letter that arrived yesterday morning
but she said that she had not been at home during the whole afternoon

if you want to learn a new skill you should practise it every day for at least
an hour because steady effort over a long period of time will always produce
better results than a short burst of hard work followed by many weeks of rest
the teacher explained the idea again and again until every student in the
class understood the point and could use it to answer the questions on the test

the old man walked slowly down the narrow street holding a small bag of food
that he had bought from the shop at the corner near the church where the bell
was ringing for the evening service and the light from the windows fell across
the wet stones of the road making them shine in the dark of the late hour

we should never trust a system that we do not understand because hidden
problems can stay inside it for many years until one day the whole thing fails
at the worst possible moment and then everyone asks why nobody checked the
details before it was too late to do anything about the damage that was done

when the police arrived at the house they found the door open and the lights
off and there were clear signs that someone had entered the room from the back
window leaving muddy marks on the floor and a broken piece of glass near the
table where the laptop had been sitting only a few hours earlier that morning

the report showed that sales had risen by a large amount during the last six
months and that the main reason for this growth was the new product line which
had been designed by the young engineer who joined the firm only last winter
and who had brought with him a fresh way of thinking about the old questions

she looked out of the window at the rain and thought about the long journey
that lay ahead of her and about all the places that she had never seen before
and about the friends that she would have to leave behind in this small town
where she had lived for the whole of her life since the day that she was born

it is important to keep a clear record of every test that you run and of every
result that you get because without good notes it is almost impossible to know
later on what was tried and what worked and what failed and why the answer was
not the one that you expected to find when you first started the whole process

the doctor told him that he would need to rest for at least a week and that he
should not go back to work until the pain had gone away completely and that he
should eat well and sleep as much as he could while his body was still weak and
in need of time to heal itself after the long illness that had kept him in bed

in the early days of the internet very few people could have predicted how
much of modern life would come to depend on networks of machines that talk to
each other at great speed across almost every part of the world and how much
of the data that passes through them each day would be private in nature

the letters that were found in the drawer dated back to the second world war
and told the story of a young soldier who had written home from a foreign field
describing the cold and the fear and the small moments of beauty that he found
in the middle of the horror that surrounded him and his companions each day

if the key is small enough then the message that was encrypted with it can be
read by anyone who knows the method because the strength of the system lies in
the size of the numbers and not in the secrecy of the way that it works and so
a weak choice of parameter can break the whole thing even if the design is good

the committee met on the first tuesday of every month to review the progress
of the projects that had been agreed at the start of the year and to decide
which of them should receive more money and which should be stopped because
they were not delivering the results that had been promised to the members

he remembered the day that he first saw the sea and how wide it had seemed
and how the sound of the waves had filled him with a strange kind of peace
that he had never felt before in the city where the noise of the traffic and
the crowds of people had always seemed to press in on him from every side

there is a common mistake that beginners make when they start to look at a
hard problem and that is to try to solve the whole thing at once instead of
breaking it into small pieces that can be checked one at a time along the way

the woman in the red coat was standing near the entrance to the station when
the train pulled in and the crowd of passengers began to push towards the door
and she held her bag tightly against her chest and waited for the rush to end
before she moved forward and stepped up into the empty carriage behind them all
"""

(FREK_KORPUS, LOG_BIGRAM, LOG_TRIGRAM, LANTAI_BIGRAM,
 LANTAI_TRIGRAM) = _bangun_statistik(KORPUS)

# bentuk flag CTF umum - dipakai sbg konfirmasi keberhasilan dekripsi
FLAG_RE = re.compile(
    r"\b(?:flag|ctf|picoctf|hackthebox|htb|ductf|thm|ohs|fcsc|ais3|dctf"
    r"|midnight|seccon|hitcon|google|fbctf)\s*\{[^{}\s]{1,300}\}", re.I)


# ====================================================================== skor
def skor_teks(t: str) -> float:
    """Skor keterbacaan Inggris. flag{...} = menang mutlak."""
    if not t:
        return -1e18
    kecetak = sum(1 for c in t if c.isprintable() or c in "\n\t") / len(t)
    if kecetak < 0.95:
        return -1e18 + kecetak * 100
    if FLAG_RE.search(t):
        return 1e9

    huruf = [c for c in t.lower() if c.isalpha()]
    if not huruf:
        return kecetak * 50

    # (1) frekuensi huruf - chi-squared terbalik
    total = len(huruf)
    chi = 0.0
    hitung = Counter(huruf)
    for h, eks in FREK_EN.items():
        amil = hitung.get(h, 0) / total * 100.0
        e = eks or 0.01
        chi += (amil - e) ** 2 / e
    bonus_frek = max(0.0, 80.0 - chi / 8.0)

    # (2) bigram & trigram umum
    b = [t[i:i + 2].lower() for i in range(len(t) - 1)]
    g = [t[i:i + 3].lower() for i in range(len(t) - 2)]
    bonus_ngram = sum(3 for x in b if x in BIGRAM_UMUM) + \
        sum(5 for x in g if x in TRIGRAM_UMUM)

    # (3) kosakata
    kata = re.findall(r"[A-Za-z']+", t.lower())
    bonus_kata = sum(8 for w in kata if w in KATA_UMUM)

    return kecetak * 60 + bonus_frek + bonus_ngram + bonus_kata


# ==================================================================== dasar
def caesar(t: str, k: int) -> str:
    k %= 26
    peta = str.maketrans(ALF + ALF.upper(),
                         ALF[k:] + ALF[:k] + ALF.upper()[k:] + ALF.upper()[:k])
    return t.translate(peta)


def atbash(t: str) -> str:
    return t.translate(str.maketrans(ALF + ALF.upper(),
                                     ALF[::-1] + ALF.upper()[::-1]))


def vigenere(t: str, kunci: str, geser: int = -1) -> str:
    """geser=-1 = DEKRIPSI (geser mundur), +1 = enkripsi."""
    kunci = [c for c in kunci.lower() if c.isalpha()]
    if not kunci:
        return t
    keluar, i = [], 0
    for c in t:
        if c.isalpha():
            dasar = string.ascii_uppercase if c.isupper() else string.ascii_lowercase
            g = (ord(kunci[i % len(kunci)]) - ord("a")) * geser
            keluar.append(dasar[(dasar.index(c) + g) % 26])
            i += 1
        else:
            keluar.append(c)
    return "".join(keluar)


def rail_fence(t: str, rails: int) -> str:
    """DEKRIPSI rail fence. Enkripsi = `rail_fence_enkrip`."""
    if rails < 2:
        return t
    n = len(t)
    pola = []
    baris, arah = 0, 1
    for _ in range(n):
        pola.append(baris)
        baris += arah
        if baris == 0 or baris == rails - 1:
            arah *= -1
    jumlah = Counter(pola)
    potongan, idx = [], 0
    for r in range(rails):
        c = jumlah[r]
        potongan.append(t[idx:idx + c])
        idx += c
    posisi = [0] * rails
    keluar = []
    for b in pola:
        keluar.append(potongan[b][posisi[b]])
        posisi[b] += 1
    return "".join(keluar)


def rail_fence_enkrip(t: str, rails: int) -> str:
    if rails < 2:
        return t
    baris: list[list[str]] = [[] for _ in range(rails)]
    r, arah = 0, 1
    for c in t:
        baris[r].append(c)
        r += arah
        if r == 0 or r == rails - 1:
            arah *= -1
    return "".join("".join(x) for x in baris)


def transposisi_kolom(t: str, kunci: int) -> str:
    """DEKRIPSI transposisi kolom (ditulis per baris, dibaca per kolom).

    Panjang kolom bisa beda kalau panjang teks tak kelipatan kunci - kolom
    awal kebagian 1 karakter ekstra. Salah menghitung di sini bikin hasilnya
    acak total, jadi dibuat eksplisit.
    """
    if kunci < 2 or not t:
        return t
    dasar, sisa = divmod(len(t), kunci)
    panjang_kolom = [dasar + (1 if c < sisa else 0) for c in range(kunci)]
    grid = [[""] * kunci for _ in range(dasar + (1 if sisa else 0))]
    pos = 0
    for c in range(kunci):
        for r in range(panjang_kolom[c]):
            grid[r][c] = t[pos]
            pos += 1
    return "".join("".join(row) for row in grid).rstrip()


def transposisi_kolom_enkrip(t: str, kunci: int) -> str:
    if kunci < 2 or not t:
        return t
    grid = [t[i:i + kunci] for i in range(0, len(t), kunci)]
    keluar = []
    for c in range(kunci):
        for row in grid:
            if c < len(row):
                keluar.append(row[c])
    return "".join(keluar)


# ==================================================== penyelesai: caesar
def selesai_caesar(cipher: str) -> list[tuple[str, str, float]]:
    hasil = []
    for k in range(26):
        p = caesar(cipher, k)
        hasil.append((f"caesar k={k}", p, skor_teks(p)))
    hasil.sort(key=lambda x: -x[2])
    return hasil


# ============================== penyelesai: substitusi alfabet tunggal
def _huruf_murni(t: str) -> str:
    return "".join(c for c in t.upper() if c.isalpha())


class SubstScorer:
    """Penilai substitusi INCREMENTAL.

    Versi naive membangun ulang plaintext tiap kali satu pasangan huruf
    ditukar. Itu O(panjang teks) per evaluasi -> 40 restart x 325 swap jadi
    puluhan juta operasi, bisa makan menit. Di sini yang dihitung ulang hanya
    bigram/trigram yang MENGANDUNG salah satu huruf yang tertukar (biasanya
    ~30 entri, bukan ~200) sehingga satu putaran penuh cukup beberapa detik.
    """

    def __init__(self, huruf_cipher: str):
        # WAJIB huruf kecil: seluruh perhitungan index pakai ord(c)-97.
        # Cipher sering berupa HURUF BESAR - kalau tak dinormalkan, indeksnya
        # negatif dan IndexError keluar di entri pertama.
        self.huruf = huruf_cipher.lower()
        n = len(self.huruf)
        self.bigram = Counter(self.huruf[i:i + 2] for i in range(n - 1))
        self.trigram = Counter(self.huruf[i:i + 3] for i in range(n - 2))
        self.freq = Counter(self.huruf)
        self.total = n or 1
        self.perm = list(ALF)
        self.skor = self._penuh()

    def _P(self, ch: str, i: int, j: int) -> str:
        """Huruf plaintext untuk ch, dengan perm[i]<->perm[j] (tanpa mutasi perm)."""
        idx = ord(ch) - 97
        if idx == i:
            idx = j
        elif idx == j:
            idx = i
        return self.perm[idx]

    def _nilai_bigram(self, cb: str, i: int = -1, j: int = -1) -> float:
        if i < 0:
            p = self.perm[ord(cb[0]) - 97] + self.perm[ord(cb[1]) - 97]
        else:
            p = self._P(cb[0], i, j) + self._P(cb[1], i, j)
        return LOG_BIGRAM.get(p, LANTAI_BIGRAM)

    def _nilai_trigram(self, tg: str, i: int = -1, j: int = -1) -> float:
        if i < 0:
            p = "".join(self.perm[ord(c) - 97] for c in tg)
        else:
            p = "".join(self._P(c, i, j) for c in tg)
        return LOG_TRIGRAM.get(p, LANTAI_TRIGRAM)

    @staticmethod
    def _log_frek(ch: str) -> float:
        p = FREK_EN[ch] / 100.0
        return math.log10(p if p > 0 else 1e-6)

    def _penuh(self) -> float:
        """Skor log-kemungkinan: sum bigram + trigram + unigram.

        Skala ketiganya konsisten (semua log10 probabilitas) - kalau dicampur
        dengan skala buatan, istilah yang lebih besar akan mendominasi dan
        menutupi sinyal yang sebenarnya.
        """
        s = 0.0
        for cb, cnt in self.bigram.items():
            s += cnt * self._nilai_bigram(cb)
        for tg, cnt in self.trigram.items():
            s += cnt * self._nilai_trigram(tg)
        for i, c in enumerate(self.perm):
            s += self.freq[ALF[i]] * self._log_frek(c)
        return s

    def _delta(self, i: int, j: int) -> float:
        lf = self._log_frek
        d = (self.freq[ALF[i]] * (lf(self.perm[j]) - lf(self.perm[i]))
             + self.freq[ALF[j]] * (lf(self.perm[i]) - lf(self.perm[j])))
        for cb, cnt in self.bigram.items():
            if ALF[i] in cb or ALF[j] in cb:
                d += cnt * (self._nilai_bigram(cb, i, j)
                            - self._nilai_bigram(cb))
        for tg, cnt in self.trigram.items():
            if ALF[i] in tg or ALF[j] in tg:
                d += cnt * (self._nilai_trigram(tg, i, j)
                            - self._nilai_trigram(tg))
        return d

    def tukar_jika_membaik(self, i: int, j: int) -> bool:
        """Tukar perm[i]<->perm[j] hanya kalau skor naik. Return: berhasil?"""
        d = self._delta(i, j)
        if d > 0:
            self.perm[i], self.perm[j] = self.perm[j], self.perm[i]
            self.skor += d
            return True
        return False


# Kamus tambahan dari file (opsional). Diisi oleh main() lewat --kamus.
# Dipakai bersama KATA_UMUM - daftar bawaan memang sengaja kecil agar
# kit ini tetap mandiri tanpa file eksternal.
KAMUS_TAMBAHAN: set[str] = set()


def _terapkan(cipher: str, kunci: str) -> str:
    """Peta cipher -> plaintext, menjaga huruf besar/kecil aslinya."""
    peta = str.maketrans(ALF + ALF.upper(), kunci + kunci.upper())
    return cipher.translate(peta)


def _hitung_kata(cipher: str, kunci: str) -> int:
    """Berapa banyak kata di hasil dekripsi yang ada di daftar kosakata."""
    teks = _terapkan(cipher, kunci).lower()
    return sum(1 for w in re.findall(r"[a-z']+", teks)
               if w in KATA_UMUM or w in KAMUS_TAMBAHAN)


def _haluskan_substitusi(cipher: str, kunci: str, iterasi: int = 8) -> str:
    """Tahap akhir berbasis KOSAKATA.

    Hill-climb n-gram hampir selalu berhenti dengan 2-4 huruf langka masih
    tertukar (BROWN->LROJN, QUICK->QUIFP) karena huruf seperti j/q/z/x cuma
    muncul sekali dan tak cukup sinyal statistiknya. Pendekatannya: hitung
    kata yang dikenal, lalu tukar pasangan huruf selama jumlahnya naik.
    Bertolak belakang dari statistik n-gram, sinyalnya DISKRET jadi huruf
    langka tadi langsung terkunci begitu kata yang benar muncul.
    """
    best, best_n = kunci, _hitung_kata(cipher, kunci)
    for _ in range(max(1, iterasi)):
        ada = False
        for i in range(26):
            for j in range(i + 1, 26):
                cand = list(best)
                cand[i], cand[j] = cand[j], cand[i]
                cand = "".join(cand)
                n = _hitung_kata(cipher, cand)
                if n > best_n:
                    best, best_n = cand, n
                    ada = True
        if not ada:
            break
    return best


def selesai_substitusi(cipher: str, restart: int = 40
                       ) -> list[tuple[str, str, float]]:
    """Hill-climb monoalphabetic substitution.

    Tiap restart mulai dari permutasi acak lalu tukar pasangan huruf selama
    skor naik. Karena skoringnya incremental (lihat SubstScorer), 40 restart
    cukup untuk beberapa detik - bukan menit.
    """
    huruf = _huruf_murni(cipher)
    if len(huruf) < 8:
        return []
    import random
    rng = random.Random(1337)      # deterministik: hasil bisa direproduksi

    terbaik: list[tuple[float, list[str]]] = []
    for _ in range(max(1, restart)):
        sc = SubstScorer(huruf)
        sc.perm = list(ALF)
        rng.shuffle(sc.perm)
        sc.skor = sc._penuh()
        while True:
            # satu pass = coba SEMUA 325 pasangan dan terapkan semua yang
            # membaik. Versi `any()` berhenti di swap pertama yang berhasil
            # lalu memindai ulang 325 pasangan dari awal - boros dan lambat.
            ada = False
            for i in range(26):
                for j in range(i + 1, 26):
                    if sc.tukar_jika_membaik(i, j):
                        ada = True
            if not ada:
                break
        terbaik.append((sc.skor, sc.perm[:]))

    terbaik.sort(key=lambda x: -x[0])
    keluar, dilihat = [], set()
    for skrg, perm in terbaik[:5]:
        kunci = "".join(perm)
        if kunci in dilihat:
            continue
        # tahap akhir: kunci dihaluskan berdasarkan kosakata, baru dinilai
        kunci = _haluskan_substitusi(cipher, kunci)
        if kunci in dilihat:
            continue
        dilihat.add(kunci)
        p = _terapkan(cipher, kunci)
        keluar.append((f"substitusi kunci={kunci}", p, skor_teks(p)))
    return keluar


# ==================================================== penyelesai: XOR
def _ke_biner(s: str) -> bytes | None:
    """Terima hex ATAU teks biasa."""
    bersih = "".join(s.split())
    if re.fullmatch(r"[0-9a-fA-F]+", bersih) and len(bersih) % 2 == 0 \
            and len(bersih) >= 4:
        try:
            return bytes.fromhex(bersih)
        except ValueError:
            pass
    return s.encode("latin-1", "replace")


def _xor(b: bytes, k: bytes) -> bytes:
    return bytes(b[i] ^ k[i % len(k)] for i in range(len(b)))


def selesai_xor(cipher: str) -> list[tuple[str, str, float]]:
    b = _ke_biner(cipher)
    if not b:
        return []
    hasil = []
    # (a) kunci 1 byte
    for k in range(256):
        r = _xor(b, bytes([k])).decode("latin-1", "replace")
        hasil.append((f"xor key=0x{k:02x} (1 byte)", r, skor_teks(r)))
    # (b) kunci berulang - tebak panjang via Index of Coincidence
    hasil += _xor_berulang(b)
    hasil.sort(key=lambda x: -x[2])
    return hasil


def _indeks_koincidence(kolom: bytes) -> float:
    n = len(kolom)
    if n < 2:
        return 0.0
    c = Counter(kolom)
    return sum(v * (v - 1) for v in c.values()) / (n * (n - 1))


def _xor_berulang(b: bytes) -> list[tuple[str, str, float]]:
    """IDX of Coincidence ~0.066 utk Inggris (teks ter-encode) -> panjang kunci
    benar punya IC kolom mendekati 0.066, bukan ~0.038 (acak)."""
    if len(b) < 8:
        return []
    kandidat = []
    for L in range(1, min(21, len(b) // 2)):
        ic = sum(_indeks_koincidence(b[i::L]) for i in range(L)) / L
        kandidat.append((L, ic))
    # ambil panjang dengan IC tertinggi
    kandidat.sort(key=lambda x: -x[1])
    keluar = []
    for L, ic in kandidat[:6]:
        kunci = bytearray()
        for i in range(L):
            kol = b[i::L]
            terbaik, skrg = 0, -1e18
            for k in range(256):
                s = skor_teks(bytes(x ^ k for x in kol).decode("latin-1", "replace"))
                if s > skrg:
                    skrg, terbaik = s, k
            kunci.append(terbaik)
        r = _xor(b, bytes(kunci)).decode("latin-1", "replace")
        keluar.append((f"xor kunci berulang (L={L}, IC={ic:.3f}, "
                       f"key={bytes(kunci)!r})", r, skor_teks(r)))
    return keluar


# ==================================================== penyelesai: Vigenere
def _panjang_kunci_vigenere(cipher: str, maks: int = 20) -> list[tuple[int, float]]:
    huruf = _huruf_murni(cipher)
    n = len(huruf)
    if n < 10:
        return []
    skor = []
    for L in range(1, min(maks + 1, n // 2)):
        ic = sum(_indeks_koincidence(huruf[i::L].encode()) for i in range(L)) / L
        skor.append((L, ic))
    skor.sort(key=lambda x: -x[1])
    return skor


def selesai_vigenere(cipher: str, kunci: str | None = None
                     ) -> list[tuple[str, str, float]]:
    if kunci:
        p = vigenere(cipher, kunci, geser=-1)
        return [(f"vigenere kunci={kunci}", p, skor_teks(p))]
    keluar = []
    for L, ic in _panjang_kunci_vigenere(cipher)[:4]:
        huruf = _huruf_murni(cipher)
        kunci = ""
        for i in range(L):
            kol = huruf[i::L]
            terbaik, skrg = "a", -1e18
            for k in range(26):
                s = skor_teks(caesar(kol, k))
                if s > skrg:
                    skrg, terbaik = s, k
            kunci += ALF[terbaik]
        p = vigenere(cipher, kunci, geser=-1)
        keluar.append((f"vigenere L={L} kunci={kunci!r} (IC={ic:.3f})",
                       p, skor_teks(p)))
    keluar.sort(key=lambda x: -x[2])
    return keluar


# ==================================================== penyelesai: rail fence
def selesai_rail(cipher: str) -> list[tuple[str, str, float]]:
    keluar = []
    for rails in range(2, 11):
        p = rail_fence(cipher, rails)
        keluar.append((f"rail-fence rails={rails}", p, skor_teks(p)))
    keluar.sort(key=lambda x: -x[2])
    return keluar


def selesai_transposisi(cipher: str) -> list[tuple[str, str, float]]:
    keluar = []
    for k in range(2, 13):
        p = transposisi_kolom(cipher, k)
        keluar.append((f"transposisi kolom={k}", p, skor_teks(p)))
    keluar.sort(key=lambda x: -x[2])
    return keluar


# ==================================================================== RSA
def _akar_pangkat(n: int, e: int) -> int:
    if n < 0:
        return -1
    if n == 0:
        return 0
    x = 1 << ((n.bit_length() + e - 1) // e)
    while True:
        y = ((e - 1) * x + n // x ** (e - 1)) // e
        if y >= x:
            return x
        x = y


def _is_square(n: int) -> bool:
    if n < 0:
        return False
    r = math.isqrt(n)
    return r * r == n


def rsa_akar_kecil(n: int, e: int, c: int) -> list[tuple[str, str]]:
    """Kalau m^e < n, maka c == m^e (modul tak pernah jalan) -> cukup akar."""
    m = _akar_pangkat(c, e)
    if pow(m, e) == c and pow(m, e) < n:
        return [("e kecil / m^e < n: cukup akar pangkat", _ke_teks(m))]
    return []


def rsa_common_factor(ns: list[int]) -> list[tuple[str, str]]:
    """Kalau dua modulus punya faktor prima sama, keduanya langsung pecah."""
    keluar = []
    for i in range(len(ns)):
        for j in range(i + 1, len(ns)):
            g = math.gcd(ns[i], ns[j])
            if g > 1 and g < ns[i]:
                p, q = g, ns[i] // g
                keluar.append((
                    f"common factor: gcd(n{i+1}, n{j+1}) = {g}",
                    f"n{i+1} = {p} x {q}"))
                p2, q2 = g, ns[j] // g
                keluar.append((f"n{j+1} pecah juga", f"n{j+1} = {p2} x {q2}"))
    return keluar


def rsa_wiener(e: int, n: int) -> list[tuple[str, str]]:
    """Wiener attack: d kecil -> pecah lewat pecahan lanjutan e/n."""
    keluar = []
    pecahan = []
    a, b = n, e
    while b:
        pecahan.append(a // b)
        a, b = b, a % b
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for x in pecahan:
        p0, p1 = p1, x * p1 + p0
        q0, q1 = q1, x * q1 + q0
        k, d = q0, p1
        if k == 0:
            continue
        if (e * d - 1) % k:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if _is_square(disc):
            keluar.append((f"Wiener: d = {d}", f"phi = {phi}"))
            return keluar
    return keluar


def rsa_fermat(n: int, batas: int = 200_000) -> list[tuple[str, str]]:
    """Fermat: kalau p dan q dekat, n = a^2 - b^2 mudah ditemukan."""
    a = math.isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(batas):
        b2 = a * a - n
        if _is_square(b2):
            b = math.isqrt(b2)
            p, q = a - b, a + b
            if p * q == n:
                return [("Fermat (p ~ q)", f"n = {p} x {q}")]
        a += 1
    return []


def rsa_pollard_p1(n: int, batas: int = 200_000) -> list[tuple[str, str]]:
    """Pollard p-1: kalau p-1 hanya berfaktor halus."""
    if n % 2 == 0:
        return [("faktor 2", f"n = 2 x {n // 2}")]
    a = 2
    batas_prima = min(batas, 100_000)
    sieve = bytearray(b"\x01") * (batas_prima + 1)
    for i in range(2, int(batas_prima ** 0.5) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    for p in range(2, batas_prima + 1):
        if not sieve[p]:
            continue
        pp = p
        while pp * p <= batas_prima:
            pp *= p
        a = pow(a, pp, n)
        if p % 256 == 0 or p == batas_prima:      # cek berkala saja, hemat gcd
            g = math.gcd(a - 1, n)
            if 1 < g < n:
                return [("Pollard p-1", f"n = {g} x {n // g}")]
    g = math.gcd(a - 1, n)
    if 1 < g < n:
        return [("Pollard p-1", f"n = {g} x {n // g}")]
    return []


def rsa_decrypt(n: int, e: int, c: list[int], label: str,
                phi: int | None = None, d: int | None = None,
                p: int | None = None, q: int | None = None) -> list[tuple[str, str]]:
    """Setelah faktor/phi/d diketahui, dekripsikan SEMUA ciphertext."""
    keluar = []
    try:
        if d is None:
            if phi is None:
                if p and q:
                    phi = (p - 1) * (q - 1)
                else:
                    return keluar
            d = pow(e, -1, phi)
        for i, ci in enumerate(c):
            m = pow(ci, d, n)
            keluar.append((f"{label} -> c[{i}]", _ke_teks(m)))
    except ValueError as exc:
        keluar.append((f"{label}: gagal", f"e tak punya invers mod phi ({exc})"))
    return keluar


def _ke_teks(m: int) -> str:
    """Bilangan -> teks. Coba big-endian standar; kalau bukan teks, tampilkan hex."""
    panjang = (m.bit_length() + 7) // 8 or 1
    b = m.to_bytes(panjang, "big")
    for enc in ("utf-8", "latin-1"):
        try:
            t = b.decode(enc)
        except UnicodeDecodeError:
            continue
        if all(c.isprintable() or c in "\n\t" for c in t) and t.strip():
            return t
    return f"(non-teks) {b.hex()}"


def rsa_analisis(n: int, e: int, cs: list[int],
                 ns_tambahan: list[int] | None = None
                 ) -> list[tuple[str, str]]:
    """Coba SELURUH metode RSA yang masuk akal. Kembalikan (metode, hasil)."""
    keluar: list[tuple[str, str]] = []
    keluar += rsa_akar_kecil(n, e, cs[0] if cs else 0)
    if ns_tambahan:
        keluar += rsa_common_factor([n] + ns_tambahan)
    keluar += rsa_wiener(e, n)
    keluar += rsa_fermat(n)
    keluar += rsa_pollard_p1(n)

    # kalau ada metode yang menghasilkan phi/d/p/q, dekripsikan
    for label, isi in list(keluar):
        m = re.search(r"d = (\d+)", label)
        if m:
            keluar += rsa_decrypt(n, e, cs, label, d=int(m.group(1)))
        m = re.search(r"phi = (\d+)", isi or "")
        if m:
            keluar += rsa_decrypt(n, e, cs, label, phi=int(m.group(1)))
        m = re.search(r"n = (\d+) x (\d+)", isi or "")
        if m:
            keluar += rsa_decrypt(n, e, cs, label,
                                  p=int(m.group(1)), q=int(m.group(2)))
    return keluar


# ==================================================================== hash
PANJANG_HASH = {
    8: "crc32 (bukan kriptografis)", 32: "md5 / ntlm", 40: "sha1",
    56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512",
}


def identifikasi_hash(s: str) -> list[str]:
    s = s.strip().lower()
    keluar = []
    if not re.fullmatch(r"[0-9a-f]+", s):
        return [f"bukan heksadesimal murni ({len(s)} char) - bukan hash umum"]
    d = PANJANG_HASH.get(len(s))
    if d:
        keluar.append(f"{len(s)} hex -> {d}")
    if len(s) == 32:
        keluar.append("  catatan: md5 & ntlm sama-sama 32 hex, beda di input")
    if len(s) in (8, 16):
        keluar.append("  kemungkinan besar hash TRUNCATED (bukan kriptografis)")
    return keluar or [f"{len(s)} hex - tak ada di tabel umum"]


def _mutasi(kata: str):
    yield kata
    yield kata.lower()
    yield kata.upper()
    yield kata.capitalize()
    yield kata[::-1]
    for suf in ("123", "1234", "2024", "2025", "2026", "!", "!@#", "1"):
        yield kata + suf
        yield kata.capitalize() + suf


def crack_hash(target: str, wordlist: list[str]) -> tuple[str, str] | None:
    target = target.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", target):
        return None
    panjang = len(target)
    fungsi = {32: hashlib.md5, 40: hashlib.sha1, 56: hashlib.sha224,
              64: hashlib.sha256, 96: hashlib.sha384, 128: hashlib.sha512}
    fn = fungsi.get(panjang)
    if fn is None:
        return None
    for kata in wordlist:
        for kandidat in _mutasi(kata.strip()):
            if not kandidat:
                continue
            if fn(kandidat.encode()).hexdigest() == target:
                return kandidat, fn.__name__
    return None


# ==================================================================== AES
def deteksi_aes_mode(b: bytes) -> list[str]:
    keluar = []
    if len(b) % 16 == 0 and len(b) >= 32:
        blok = [b[i:i + 16] for i in range(0, len(b), 16)]
        if len(set(blok)) < len(blok):
            keluar.append("ECB sangat mungkin: ada blok 16-byte IDENTIK berulang")
        else:
            keluar.append("tiap blok 16-byte unik -> ECB tak terlihat "
                          "(bisa tetap ECB kalau datanya pendek)")
    else:
        keluar.append(f"panjang {len(b)} bukan kelipatan 16 -> bukan AES-ECB mentah")
    return keluar


def aes_decrypt_ecb(b: bytes, kunci: bytes) -> str:
    try:
        from Cryptodome.Cipher import AES
    except ImportError:
        return "[ Cryptodome tak tersedia - tak bisa dekripsi AES di mesin ini ]"
    if len(kunci) not in (16, 24, 32):
        return f"[ kunci {len(kunci)} byte - AES butuh 16/24/32 ]"
    c = AES.new(kunci, AES.MODE_ECB)
    return c.decrypt(b).rstrip(b"\x00").decode("latin-1", "replace")


# ==================================================================== main
def _tampilkan(judul: str, hasil: list[tuple[str, str, float]], top: int) -> int:
    if not hasil:
        return 0
    print(f"\n--- {judul} ---")
    dilihat = set()
    n = 0
    for label, p, s in hasil:
        if p in dilihat or s < -1e17:
            continue
        dilihat.add(p)
        tanda = "  <== FLAG" if FLAG_RE.search(p) else ""
        print(f"  [{s:9.1f}] {label}{tanda}")
        print(f"           {_potong(p)}")
        n += 1
        if n >= top:
            break
    return n


def _potong(s: str, n: int = 150) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + f"... [+{len(s)-n}]"


def _angka(s: str) -> int:
    s = s.strip().replace("_", "")
    return int(s, 16) if s.lower().startswith("0x") else int(s)


def main() -> int:
    ap = argparse.ArgumentParser(description="penyelesai cipher & kripto CTF")
    ap.add_argument("teks", nargs="?", default="", help="ciphertext")
    ap.add_argument("--in", dest="inp", default="", help="baca dari file")
    ap.add_argument("--caesar", action="store_true")
    ap.add_argument("--substitution", action="store_true")
    ap.add_argument("--xor", action="store_true")
    ap.add_argument("--vigenere", action="store_true")
    ap.add_argument("--rail", action="store_true")
    ap.add_argument("--transposisi", action="store_true")
    ap.add_argument("--hash", action="store_true", help="kenali/pecahkan hash")
    ap.add_argument("--wordlist", default="", help="wordlist utk crack hash")
    ap.add_argument("--rsa", action="store_true")
    ap.add_argument("--n", action="append", default=[], help="modulus (boleh >1)")
    ap.add_argument("--e", default="", help="exponen publik")
    ap.add_argument("--c", action="append", default=[], help="ciphertext (boleh >1)")
    ap.add_argument("--aes", action="store_true")
    ap.add_argument("--hex", action="store_true", help="input adalah hex")
    ap.add_argument("--kunci", default="", help="kunci AES (hex) utk --aes")
    ap.add_argument("--kamus", default="",
                    help="file kamus (1 kata/baris) utk memperkuat "
                         "--substitution - opsional, daftar bawaan tetap jalan")
    ap.add_argument("--restart", type=int, default=40,
                    help="restart hill-climb substitusi (default 40)")
    ap.add_argument("--top", type=int, default=5, help="kandidat per metode")
    a = ap.parse_args()

    if a.kamus:
        try:
            with open(a.kamus, encoding="utf-8", errors="replace") as fh:
                for baris in fh:
                    w = baris.strip().lower()
                    if w.isalpha():
                        KAMUS_TAMBAHAN.add(w)
        except OSError as exc:
            print(f"[STOP] tak bisa baca kamus {a.kamus}: {exc}", file=sys.stderr)
            return 1
        if not KAMUS_TAMBAHAN:
            print(f"[!] kamus {a.kamus} tak berisi kata apa pun")
        else:
            print(f"[*] kamus {a.kamus}: {len(KAMUS_TAMBAHAN)} kata")

    if a.n or a.c or a.e:
        a.rsa = True
    if a.rsa and not (a.n and a.e):
        ap.error("--rsa butuh --n dan --e (dan --c bila mau dekripsi)")

    # ------------------------------------------------------- RSA
    if a.rsa:
        n = _angka(a.n[0])
        e = _angka(a.e)
        cs = [_angka(x) for x in a.c]
        lain = [_angka(x) for x in a.n[1:]]
        print(f"[*] RSA  n ({n.bit_length()} bit)  e={e}  "
              f"ciphertext={len(cs)} buah")
        hasil = rsa_analisis(n, e, cs, lain)
        if not hasil:
            print("\n[i] tak ada metode yang berhasil. Yang sudah dicoba:")
            print("    e kecil / akar pangkat - common factor antar modulus")
            print("    Wiener (d kecil) - Fermat (p ~ q) - Pollard p-1")
            print("    kalau ada publik.pem berisi banyak n, gabung dgn --n n1 --n n2")
        for label, isi in hasil:
            tanda = "  <== FLAG" if FLAG_RE.search(isi) else ""
            print(f"  {label}{tanda}")
            print(f"      {_potong(isi, 200)}")
        return 0

    # ------------------------------------------------------- hash
    if a.hash:
        teks = a.teks.strip() or (open(a.inp).read().strip() if a.inp else "")
        if not teks:
            ap.error("--hash butuh target hash")
        print(f"[*] identifikasi {teks[:70]}...")
        for b in identifikasi_hash(teks):
            print(f"  {b}")
        daftar = []
        if a.wordlist:
            try:
                daftar = open(a.wordlist, encoding="utf-8",
                              errors="replace").read().splitlines()
            except OSError as exc:
                print(f"[STOP] tak bisa baca wordlist: {exc}", file=sys.stderr)
                return 1
            print(f"[*] wordlist {a.wordlist}: {len(daftar)} baris + mutasi")
            temuan = crack_hash(teks, daftar)
            if temuan:
                print(f"\n[PECET] {temuan[1]}({temuan[0]!r})")
            else:
                print("\n[i] tak ketemu di wordlist tsb (termasuk mutasinya)")
        else:
            print("[i] pakai --wordlist FILE utk mencoba memecah")
        return 0

    # ------------------------------------------------------- AES
    if a.aes:
        raw = a.hex and re.fullmatch(r"[0-9a-fA-F\s]+", a.teks or "")
        if a.inp:
            isi = open(a.inp, "rb").read()
        elif a.hex:
            isi = bytes.fromhex("".join(a.teks.split()))
        else:
            isi = a.teks.encode("latin-1", "replace")
        print(f"[*] {len(isi)} byte")
        for b in deteksi_aes_mode(isi):
            print(f"  {b}")
        if a.kunci:
            k = bytes.fromhex(a.kunci)
            print(f"\n[*] dekripsi AES-ECB dgn kunci {len(k)} byte")
            print(f"    {_potong(aes_decrypt_ecb(isi, k))}")
        else:
            print("[i] beri --kunci HEX bila sudah tahu kuncinya")
        return 0

    # ------------------------------------------------------- teks biasa
    teks = a.teks
    if a.inp:
        try:
            teks = open(a.inp, encoding="utf-8", errors="replace").read().strip()
        except OSError as exc:
            print(f"[STOP] gagal baca {a.inp}: {exc}", file=sys.stderr)
            return 1
    if not teks:
        ap.error("butuh argumen teks atau --in FILE")

    print(f"[*] input: {_potong(teks)}")
    if FLAG_RE.search(teks):
        print("[!] sudah ada flag{...} apa adanya - tak perlu didekripsi")
        return 0

    total = 0
    if a.caesar:
        total += _tampilkan("Caesar (26 rotasi)", selesai_caesar(teks), a.top)
    if a.substitution:
        total += _tampilkan("Substitution (hill-climb)",
                            selesai_substitusi(teks, a.restart), a.top)
    if a.xor:
        total += _tampilkan("XOR (1 byte + kunci berulang)",
                            selesai_xor(teks), a.top)
    if a.vigenere:
        total += _tampilkan("Vigenere", selesai_vigenere(teks), a.top)
    if a.rail:
        total += _tampilkan("Rail fence", selesai_rail(teks), a.top)
    if a.transposisi:
        total += _tampilkan("Transposisi kolom", selesai_transposisi(teks), a.top)

    if not any([a.caesar, a.substitution, a.xor, a.vigenere, a.rail,
                a.transposisi]):
        # mode auto: coba semua, lalu laporkan mana yang paling meyakinkan
        for judul, fn in [
            ("Caesar", selesai_caesar),
            ("Vigenere", selesai_vigenere),
            ("Rail fence", selesai_rail),
            ("Transposisi kolom", selesai_transposisi),
            ("XOR", selesai_xor),
            ("Substitution (butuh teks panjang)", selesai_substitusi),
        ]:
            try:
                total += _tampilkan(judul, fn(teks), a.top)
            except Exception as exc:                      # noqa: BLE001
                print(f"  [!] {judul} gagal: {type(exc).__name__}: {exc}")
        if not total:
            print("\n[i] tak ada metode yang menghasilkan teks terbaca.")
            print("    Kalau bentuknya heksadesimal panjang, kemungkinan ini")
            print("    hash / AES / RSA - lihat --hash / --aes / --rsa")

    return 0


if __name__ == "__main__":
    sys.exit(main())
